"""The orchestrator loop (Master Prompt §3).

Drives an engagement through INGEST → PLAN → GATE → TEST → TRIAGE → LEARN. The
non-negotiable rule: **every planned action is gated before a worker runs it**,
and budget is only committed after an allowed action executes.

The loop talks to a :class:`~aegis.orchestrator.gate.PolicyGate`, not the engine
directly, so the same loop runs against an in-process engine (``LocalGate``) or
the control-plane API (``RemoteGate``). The kill switch is detected from the
gate's own decision (a ``KILL_SWITCH`` incident), so no side channel is needed
and both gates behave identically.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field

from aegis.model import (
    AttackSurface,
    Candidate,
    EngagementInputs,
    Finding,
    PlannedAction,
)
from aegis.policy import ActionRequest, PolicyEngine, Verdict, normalize_host

from .escalation import EscalationItem, EscalationQueue, EscalationReason
from .gate import GateDecision, LocalGate, PolicyGate
from .planner import Planner
from .triage import triage
from .workers import WorkerContext, WorkerRegistry


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _host_of(target: str) -> str:
    try:
        return normalize_host(target)
    except ValueError:
        return (target or "").strip().lower()


def _kill_reason(decision: GateDecision) -> str:
    for reason in decision.as_dict().get("reasons", []):
        if reason.get("code") == "kill_switch_active":
            return reason.get("message", "kill switch active")
    return "kill switch active"


class BlockedAction(BaseModel):
    action: PlannedAction
    decision: dict


class SafetyEvent(BaseModel):
    kind: str
    detail: str = ""
    action_id: str | None = None


class EngagementRun(BaseModel):
    engagement_id: str
    stages: list[str] = Field(default_factory=list)
    surface: AttackSurface = Field(default_factory=AttackSurface)
    findings: list[Finding] = Field(default_factory=list)
    hypotheses: list[Candidate] = Field(default_factory=list)
    escalations: list[EscalationItem] = Field(default_factory=list)
    executed_action_ids: list[str] = Field(default_factory=list)
    blocked: list[BlockedAction] = Field(default_factory=list)
    safety_events: list[SafetyEvent] = Field(default_factory=list)
    halted: bool = False
    halt_reason: str | None = None

    def summary(self) -> dict:
        return {
            "engagement_id": self.engagement_id,
            "executed": len(self.executed_action_ids),
            "blocked": len(self.blocked),
            "escalations": len(self.escalations),
            "findings": len(self.findings),
            "hypotheses": len(self.hypotheses),
            "safety_events": len(self.safety_events),
            "halted": self.halted,
        }


class Orchestrator:
    def __init__(
        self,
        *,
        gate: PolicyGate | None = None,
        engine: PolicyEngine | None = None,
        planner: Planner,
        workers: WorkerRegistry,
        engagement_id: str,
        escalation_contacts: list[str] | None = None,
        approvals: dict[tuple[str, str], set[str]] | None = None,
    ) -> None:
        if (gate is None) == (engine is None):
            raise ValueError("provide exactly one of gate= or engine=")
        self.gate: PolicyGate = gate if gate is not None else LocalGate(engine)
        self.planner = planner
        self.workers = workers
        self.engagement_id = engagement_id
        self._contacts = list(escalation_contacts or [])
        # Pre-granted approval tokens keyed by (action, host), injected into the
        # request for a LocalGate. A RemoteGate ignores these — approvals are
        # granted server-side through the control plane's approval ledger.
        self._approvals = approvals or {}

    def _tokens_for(self, action: PlannedAction) -> frozenset[str]:
        return frozenset(self._approvals.get((action.action, _host_of(action.target)), set()))

    def run(self, inputs: EngagementInputs) -> EngagementRun:
        run = EngagementRun(engagement_id=self.engagement_id)
        escalations = EscalationQueue(self._contacts)
        surface = AttackSurface()
        candidates: list[Candidate] = []
        evidence_by_id: dict = {}

        # INGEST — authorization validity is enforced per-action by the gate.
        run.stages.append("INGEST")

        # PLAN
        run.stages.append("PLAN")
        plan = self.planner.plan(inputs, surface)

        # GATE + TEST
        run.stages.append("GATE/TEST")
        for action in plan.actions:
            now = _utcnow()
            request = ActionRequest(
                target=action.target,
                action=action.action,
                tier_hint=action.tier_hint,
                estimated_cost=action.estimated_cost,
                touches_production=action.touches_production,
                approvals=self._tokens_for(action),
            )
            decision = self.gate.authorize(request, now=now)

            # Kill switch (from the decision itself) halts the whole run (§8).
            if "KILL_SWITCH" in decision.incidents:
                run.halted = True
                run.halt_reason = _kill_reason(decision)
                escalations.add(
                    EscalationReason.KILL_SWITCH,
                    detail=run.halt_reason,
                    action=action,
                    decision=decision.as_dict(),
                )
                break

            if decision.verdict == Verdict.ALLOW:
                surface = self._execute(
                    action, request, decision, now, surface,
                    candidates, evidence_by_id, run, escalations,
                )
            elif decision.verdict == Verdict.REQUIRE_APPROVAL:
                escalations.add(
                    EscalationReason.APPROVAL_REQUIRED,
                    action=action,
                    decision=decision.as_dict(),
                    required_approvals=decision.required_approvals,
                )
            elif decision.verdict == Verdict.ESCALATE:
                escalations.add(
                    EscalationReason.POLICY_ESCALATE,
                    action=action,
                    decision=decision.as_dict(),
                )
            else:  # DENY
                run.blocked.append(BlockedAction(action=action, decision=decision.as_dict()))

        # TRIAGE (EVIDENCE folded in — candidates carry evidence refs)
        run.stages.append("TRIAGE")
        result = triage(candidates, evidence_by_id)
        run.findings = result.findings
        run.hypotheses = result.hypotheses

        # LEARN — outcome labels would be emitted to the feedback store here.
        run.stages.append("LEARN")

        run.surface = surface
        run.escalations = escalations.items()
        return run

    def _execute(
        self,
        action: PlannedAction,
        request: ActionRequest,
        decision: GateDecision,
        now: datetime,
        surface: AttackSurface,
        candidates: list[Candidate],
        evidence_by_id: dict,
        run: EngagementRun,
        escalations: EscalationQueue,
    ) -> AttackSurface:
        """Run one allowed action; return the (possibly updated) surface."""
        worker = self.workers.get(action.worker)
        if worker is None:
            run.blocked.append(
                BlockedAction(
                    action=action,
                    decision={"error": "no_worker_registered", "worker": action.worker},
                )
            )
            return surface

        ctx = WorkerContext(engagement_id=self.engagement_id, surface=surface, now=now)
        result = worker.run(action, ctx)

        # An allowed action that ran debits the budget (two-phase gate/commit).
        self.gate.commit(decision, request=request, now=now)

        # §5 stop-on-sensitive-data: halt this path, record, redact, escalate.
        if result.sensitive_data_encountered:
            run.safety_events.append(
                SafetyEvent(
                    kind="SENSITIVE_DATA_ENCOUNTERED",
                    detail="stopped path and redacted; raw data not stored",
                    action_id=action.id,
                )
            )
            escalations.add(
                EscalationReason.SENSITIVE_DATA,
                action=action,
                detail="real sensitive data encountered; path halted",
            )
            return surface

        for ev in result.evidence:
            evidence_by_id[ev.evidence_id] = ev
        candidates.extend(result.candidates)
        run.executed_action_ids.append(action.id)
        return surface.merge(result.surface_delta)
