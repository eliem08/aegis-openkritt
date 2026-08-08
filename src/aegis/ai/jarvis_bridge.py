"""Canonical Jarvis bridge for the live autonomous source-review hunt.

The production ``auto_hunt`` pipeline and the newer ``agentic_os`` contracts used to be
parallel worlds.  This module is their single seam: validated source findings become
canonical proposals/lifecycles, economics decides whether more research is worth buying,
quality work is policy-gated, active-network intents are visible but vetoed under the
source-review envelope, and reasoning state is persisted.

No scanner/LLM claim is promoted to reproduced evidence.  Local reproduction is a real
state change and requires the existing explicit ``AEGIS_ALLOW_REPRO=1`` operator opt-in.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .active_bridge import followup_intents_for_finding
from .agentic_os import (
    AgentProposal,
    AgentRole,
    AuthorizationEnvelope,
    Budget,
    Decision,
    EvidenceRef,
    EvidenceStage,
    FindingLifecycle,
    GraphEdge,
    ProposalPolicy,
    RiskClass,
)
from .jarvis.graph_store import SqliteSecurityKnowledgeGraph
from .jarvis.mission_scheduler import MissionScheduler, build_linear_mission
from .jarvis.profit_feedback import calibrate_opportunity
from .jarvis.state_store import JarvisStateStore
from .portfolio_agents import Opportunity


def _bounded(value: Any, default: float, low: float = 0.0, high: float = 1.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = default
    return max(low, min(high, number))


def _digest(payload: Any) -> str:
    raw = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _answer(row: dict) -> dict:
    value = row.get("json_answer")
    return value if isinstance(value, dict) else {}


def _weakness(row: dict) -> str:
    answer = _answer(row)
    return str(
        answer.get("vulnerability_type")
        or answer.get("weakness")
        or row.get("cwe")
        or "unspecified"
    ).strip()[:120]


def _location(row: dict) -> str:
    answer = _answer(row)
    return f"{answer.get('file_path', '')}:{answer.get('line', '')}".strip(":")


def _state_path(report_root: str | Path = "reports") -> Path:
    configured = os.environ.get("AEGIS_JARVIS_STATE_DB", "").strip()
    path = Path(configured) if configured else Path(report_root) / "jarvis_state.sqlite3"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def source_evidence(repository: str, row: dict) -> EvidenceRef:
    answer = _answer(row)
    material = {
        "repository": repository,
        "location": _location(row),
        "weakness": _weakness(row),
        "summary": answer.get("summary", ""),
        "validation": row.get("validation") or {},
        "reachability": row.get("reachability") or {},
        "source": row.get("source", ""),
    }
    digest = _digest(material)
    return EvidenceRef(
        evidence_id=f"source:{digest[:20]}",
        kind="source_validation",
        digest=digest,
        summary=f"{repository} {_location(row)} {_weakness(row)}"[:300],
    )


def source_review_envelope(
    authorization_decision,
    *,
    model_egress_allowed: bool,
    cost_budget_usd: float,
    human_minutes: float = 60.0,
    local_state_change_approved: bool = False,
) -> AuthorizationEnvelope:
    """Translate target authorization into the action envelope for source research.

    Live target network remains disabled.  ``local_state_change_approved`` is used only for
    an explicit disposable-local-lab opt-in; it does not authorize target-network activity.
    """
    record = getattr(authorization_decision, "record", None)
    scope_digest = str(getattr(record, "scope_snapshot_hash", "") or "")
    if not scope_digest:
        scope_digest = _digest(
            {
                "repository": getattr(authorization_decision, "repository", ""),
                "status": getattr(authorization_decision, "status", ""),
            }
        )[:16]
    return AuthorizationEnvelope(
        scope_digest=scope_digest,
        network_allowed=False,
        state_change_allowed=bool(local_state_change_approved),
        external_model_egress_allowed=bool(model_egress_allowed),
        human_approval=bool(local_state_change_approved),
        budget=Budget(
            max_cost_usd=max(0.0, float(cost_budget_usd)),
            max_requests=0,
            max_human_minutes=max(0.0, float(human_minutes)),
        ),
    )


def proposal_from_validated_row(repository: str, row: dict) -> AgentProposal:
    evidence = source_evidence(repository, row)
    validation = row.get("validation") or {}
    confidence = _bounded(validation.get("confidence"), 0.75)
    return AgentProposal(
        role=AgentRole.STATIC_ANALYSIS,
        action="promote_source_supported_candidate",
        rationale=(
            "A source candidate survived citation validation and deterministic reachability "
            "checks."
        ),
        risk=RiskClass.OFFLINE,
        expected_information_gain=max(0.35, confidence),
        expected_cost_usd=0.0,
        evidence=(evidence,),
        metadata={
            "repository": repository,
            "weakness": _weakness(row),
            "location": _location(row),
            "origin": str(row.get("source") or "aegis:llm"),
        },
    )


def lifecycle_from_validated_row(repository: str, row: dict) -> FindingLifecycle:
    evidence = source_evidence(repository, row)
    finding_id = str(row.get("finding_id") or f"finding:{evidence.digest[:24]}")
    lifecycle = FindingLifecycle(finding_id=finding_id)
    if (row.get("validation") or {}).get("verdict") == "confirmed":
        lifecycle.advance(EvidenceStage.SOURCE_SUPPORTED, (evidence,))
    return lifecycle


def _likely_payout(row: dict, target) -> float:
    enrichment = row.get("enrichment") or {}
    economics = row.get("economics") or {}
    for value in (
        enrichment.get("bounty_likely"),
        economics.get("likely_bounty"),
        getattr(target, "likely_payout", 0.0),
    ):
        try:
            amount = float(value or 0.0)
        except (TypeError, ValueError):
            continue
        if amount > 0:
            return amount
    ceiling = max(0.0, float(getattr(target, "reward_ceiling", 0.0) or 0.0))
    return ceiling * 0.30


def opportunity_from_finding(row: dict, target) -> Opportunity:
    """Convert one source-supported finding into the common portfolio EV contract."""
    validation = row.get("validation") or {}
    enrichment = row.get("enrichment") or {}
    reproduction = row.get("reproduction") or {}
    agreement = max(1, int(row.get("agreement", 1) or 1))
    samples = max(1, int(row.get("samples", agreement) or agreement))
    agreement_ratio = _bounded(agreement / samples, 0.5)
    confirmed = validation.get("verdict") == "confirmed"
    p_valid = _bounded(validation.get("confidence"), 0.82 if confirmed else 0.35)
    p_valid = min(0.97, 0.65 * p_valid + 0.35 * agreement_ratio)
    p_accept = 0.60
    if enrichment.get("trust_model_holds") is False:
        p_accept *= 0.35
    p_unique = 1.0 - _bounded(getattr(target, "duplicate_risk", 0.0), 0.20)
    if enrichment.get("likely_duplicate") is True:
        p_unique = min(p_unique, 0.20)
    repro_verdict = str(reproduction.get("verdict") or "")
    if repro_verdict == "reproduced":
        p_reproducible = 0.98
    elif repro_verdict in {"not_reproduced", "failed"}:
        p_reproducible = 0.15
    else:
        reachability = row.get("reachability") or {}
        p_reproducible = (
            0.72
            if reachability and reachability.get("verdict") != "arity-mismatch"
            else 0.55
        )
    review_minutes = float(os.environ.get("AEGIS_JARVIS_REVIEW_MINUTES", "12") or 12)
    compute_cost = float(os.environ.get("AEGIS_JARVIS_ESCALATION_COST_USD", "0.75") or 0.75)
    return Opportunity(
        opportunity_id=str(
            row.get("finding_id")
            or f"{getattr(target, 'repository', '')}:{_digest(row)[:16]}"
        ),
        program_id=str(getattr(target, "handle", "") or getattr(target, "repository", "")),
        bug_class=_weakness(row),
        expected_payout_usd=_likely_payout(row, target),
        p_valid=p_valid,
        p_accepted=p_accept,
        p_unique=p_unique,
        p_reproducible=p_reproducible,
        compute_cost_usd=max(0.0, compute_cost),
        api_cost_usd=0.0,
        review_minutes=max(0.0, review_minutes),
        opportunity_cost_usd=0.0,
        information_gain=max(0.2, p_valid),
    )


def quality_proposals(
    finding_id: str,
    *,
    local_lab_available: bool = False,
) -> tuple[AgentProposal, ...]:
    """Skeptic -> reproduction -> evidence proposals on the canonical contract."""
    skeptic_cost = float(os.environ.get("AEGIS_JARVIS_SKEPTIC_COST_USD", "0.35") or 0.35)
    repro_cost = float(os.environ.get("AEGIS_JARVIS_REPRO_COST_USD", "0.25") or 0.25)
    return (
        AgentProposal(
            role=AgentRole.JUDGE,
            action="adversarial_source_review",
            rationale=(
                "Attempt to falsify attacker control, reachability, guards, scope, impact, "
                "and duplicate assumptions."
            ),
            risk=RiskClass.OFFLINE,
            expected_information_gain=0.95,
            expected_cost_usd=max(0.0, skeptic_cost),
            requires_external_model=True,
            metadata={"finding_id": finding_id, "council_stage": "skeptic"},
        ),
        AgentProposal(
            role=AgentRole.REPRODUCTION,
            action="reproduce_in_disposable_local_lab",
            rationale=(
                "Start only an explicitly opted-in disposable localhost lab and validate with "
                "deterministic positive/negative controls."
            ),
            risk=RiskClass.CONTROLLED_STATE_CHANGE,
            expected_information_gain=1.0,
            expected_cost_usd=max(0.0, repro_cost),
            metadata={
                "finding_id": finding_id,
                "council_stage": "reproduction",
                "local_lab_available": bool(local_lab_available),
            },
        ),
        AgentProposal(
            role=AgentRole.EVIDENCE,
            action="assemble_evidence_bundle",
            rationale=(
                "Assemble immutable report-quality evidence after reproduction and independent "
                "review."
            ),
            risk=RiskClass.OFFLINE,
            expected_information_gain=0.30,
            expected_cost_usd=0.05,
            metadata={"finding_id": finding_id, "council_stage": "evidence"},
        ),
    )


def _persist_mission(
    *,
    lifecycle: FindingLifecycle,
    scope_digest: str,
    repository: str,
    report_root: str | Path,
) -> str:
    mission_id = f"mission:{lifecycle.finding_id.replace(':', '_')}"
    try:
        with JarvisStateStore(_state_path(report_root)) as store:
            scheduler = MissionScheduler(store)
            if scheduler.resume(mission_id) is None:
                scheduler.create(
                    build_linear_mission(
                        mission_id=mission_id,
                        scope_digest=scope_digest,
                        objective=f"Validate {lifecycle.finding_id} in {repository}",
                        steps=(
                            ("skeptic", AgentRole.JUDGE.value, "adversarial_source_review"),
                            (
                                "reproduce",
                                AgentRole.REPRODUCTION.value,
                                "reproduce_in_disposable_local_lab",
                            ),
                            ("evidence", AgentRole.EVIDENCE.value, "assemble_evidence_bundle"),
                        ),
                    )
                )
    except Exception:
        return ""
    return mission_id


def _persist_reasoning_graph(
    *,
    repository: str,
    row: dict,
    lifecycle: FindingLifecycle,
    mission_id: str,
    report_root: str | Path,
) -> None:
    """Persist repository/finding/weakness/evidence/mission relationships."""
    if not repository:
        return
    repo_node = f"repository:{repository.lower()}"
    finding_node = lifecycle.finding_id
    weakness = _weakness(row).lower()
    weakness_node = f"weakness:{weakness}"
    try:
        with SqliteSecurityKnowledgeGraph(_state_path(report_root)) as graph:
            graph.upsert_node(repo_node, "repository", repository=repository)
            graph.upsert_node(
                finding_node,
                "finding",
                stage=lifecycle.stage.value,
                location=_location(row),
                summary=str(_answer(row).get("summary") or "")[:500],
            )
            graph.upsert_node(weakness_node, "weakness", name=_weakness(row))
            graph.connect(GraphEdge(repo_node, "HAS_FINDING", finding_node, "jarvis_bridge"))
            graph.connect(GraphEdge(finding_node, "INSTANCE_OF", weakness_node, "jarvis_bridge"))
            for evidence in lifecycle.evidence:
                evidence_node = f"evidence:{evidence.digest}"
                graph.upsert_node(
                    evidence_node,
                    "evidence",
                    evidence_id=evidence.evidence_id,
                    evidence_kind=evidence.kind,
                    summary=evidence.summary,
                )
                graph.connect(
                    GraphEdge(finding_node, "SUPPORTED_BY", evidence_node, "jarvis_bridge")
                )
            if mission_id:
                mission_node = mission_id
                graph.upsert_node(mission_node, "mission", state="active")
                graph.connect(
                    GraphEdge(finding_node, "VALIDATED_BY_MISSION", mission_node, "jarvis_bridge")
                )
    except Exception:
        # Persistence is supporting infrastructure; it must not change a finding verdict.
        return


@dataclass(frozen=True)
class JarvisFindingDecision:
    finding_id: str
    stage: EvidenceStage
    source_decision: Decision
    net_ev_usd: float
    should_escalate: bool
    quality_decisions: tuple[Decision, ...]
    active_decisions: tuple[Decision, ...]
    mission_id: str = ""

    def as_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "stage": self.stage.value,
            "source_policy": asdict(self.source_decision),
            "net_ev_usd": round(self.net_ev_usd, 2),
            "should_escalate": self.should_escalate,
            "quality_policy": [asdict(item) for item in self.quality_decisions],
            "active_policy": [asdict(item) for item in self.active_decisions],
            "mission_id": self.mission_id,
        }


def evaluate_finding(
    row: dict,
    target,
    authorization_decision,
    *,
    report_root: str | Path = "reports",
    model_egress_allowed: bool = True,
    min_net_ev_usd: float | None = None,
    human_hour_cost_usd: float | None = None,
    local_lab_available: bool = False,
) -> JarvisFindingDecision:
    """Evaluate one live finding through policy, lifecycle, economics and persistence."""
    min_net = (
        float(os.environ.get("AEGIS_JARVIS_MIN_NET_EV", "0") or 0)
        if min_net_ev_usd is None
        else float(min_net_ev_usd)
    )
    human_cost = (
        float(os.environ.get("AEGIS_HUMAN_HOURLY_COST_USD", "20") or 20)
        if human_hour_cost_usd is None
        else float(human_hour_cost_usd)
    )
    budget = float(os.environ.get("AEGIS_JARVIS_FINDING_BUDGET_USD", "3") or 3)
    envelope = source_review_envelope(
        authorization_decision,
        model_egress_allowed=model_egress_allowed,
        cost_budget_usd=budget,
        local_state_change_approved=local_lab_available,
    )
    policy = ProposalPolicy()
    repository = str(getattr(target, "repository", "") or "")
    proposal = proposal_from_validated_row(repository, row)
    source_decision = policy.evaluate(proposal, envelope)
    lifecycle = lifecycle_from_validated_row(repository, row)

    # Target authorization is a prerequisite to the action envelope itself.  An offline proposal
    # must never be able to look "authorized" merely because it needs no network.
    if not bool(getattr(authorization_decision, "allowed", False)):
        source_decision = Decision(
            proposal.proposal_id,
            False,
            "target authorization denied: "
            + str(getattr(authorization_decision, "reason", "not authorized"))[:240],
        )
        lifecycle = FindingLifecycle(finding_id=lifecycle.finding_id)

    opportunity = opportunity_from_finding(row, target)
    try:
        with JarvisStateStore(_state_path(report_root)) as store:
            prior = store.learned_prior(opportunity.program_id, opportunity.bug_class)
            opportunity = calibrate_opportunity(opportunity, prior)
    except Exception:
        pass
    net_ev = opportunity.expected_value(max(0.0, human_cost))
    should_escalate = (
        source_decision.approved
        and lifecycle.stage is EvidenceStage.SOURCE_SUPPORTED
        and net_ev >= min_net
    )

    quality: list[Decision] = []
    for quality_proposal in quality_proposals(
        lifecycle.finding_id,
        local_lab_available=local_lab_available,
    ):
        decision = policy.evaluate(quality_proposal, envelope)
        if decision.approved and not should_escalate:
            decision = Decision(
                decision.proposal_id,
                False,
                "deferred by non-positive/low net expected value",
            )
        quality.append(decision)

    # Source findings may indicate which active lane is useful, but source review has no target
    # network authority.  These intents are therefore expected to be vetoed until an explicit
    # active engagement supplies discovered routes, budgets, state-change approval and a human.
    active = tuple(
        policy.evaluate(active_proposal, envelope)
        for active_proposal in followup_intents_for_finding(row)
    )

    mission_id = ""
    if should_escalate:
        mission_id = _persist_mission(
            lifecycle=lifecycle,
            scope_digest=envelope.scope_digest,
            repository=repository,
            report_root=report_root,
        )
    _persist_reasoning_graph(
        repository=repository,
        row=row,
        lifecycle=lifecycle,
        mission_id=mission_id,
        report_root=report_root,
    )

    result = JarvisFindingDecision(
        finding_id=lifecycle.finding_id,
        stage=lifecycle.stage,
        source_decision=source_decision,
        net_ev_usd=net_ev,
        should_escalate=should_escalate,
        quality_decisions=tuple(quality),
        active_decisions=active,
        mission_id=mission_id,
    )
    row["jarvis"] = result.as_dict()
    row["jarvis"]["opportunity"] = {
        "program_id": opportunity.program_id,
        "bug_class": opportunity.bug_class,
        "expected_payout_usd": round(opportunity.expected_payout_usd, 2),
        "p_valid": round(opportunity.p_valid, 3),
        "p_accepted": round(opportunity.p_accepted, 3),
        "p_unique": round(opportunity.p_unique, 3),
        "p_reproducible": round(opportunity.p_reproducible, 3),
        "review_minutes": round(opportunity.review_minutes, 1),
    }
    return result


def advance_reproduction(
    row: dict,
    repository: str,
    *,
    report_root: str | Path = "reports",
) -> EvidenceStage:
    """Advance source-supported evidence through real local reproduction stages.

    The stages are advanced sequentially with distinct evidence references.  A failed or missing
    reproduction leaves the finding at its current stage; setting a string to
    ``locally_reproduced`` is deliberately insufficient.
    """
    jarvis = row.get("jarvis") or {}
    if str(jarvis.get("stage") or "") != EvidenceStage.SOURCE_SUPPORTED.value:
        try:
            return EvidenceStage(str(jarvis.get("stage") or EvidenceStage.CANDIDATE.value))
        except ValueError:
            return EvidenceStage.CANDIDATE
    reproduction = row.get("reproduction") or {}
    if str(reproduction.get("verdict") or "") != "reproduced":
        return EvidenceStage.SOURCE_SUPPORTED

    lifecycle = lifecycle_from_validated_row(repository, row)
    runtime_material = {
        "repository": repository,
        "instance": reproduction.get("instance"),
        "attempts": reproduction.get("attempts"),
        "summary": reproduction.get("summary"),
    }
    runtime_digest = _digest(runtime_material)
    runtime = EvidenceRef(
        f"runtime:{runtime_digest[:20]}",
        "runtime_observation",
        runtime_digest,
        str(reproduction.get("summary") or "local runtime response observed")[:300],
    )
    lifecycle.advance(EvidenceStage.RUNTIME_OBSERVED, (runtime,))

    oracle_material = {
        "runtime": runtime_digest,
        "verdict": reproduction.get("verdict"),
        "summary": reproduction.get("summary"),
    }
    oracle_digest = _digest(oracle_material)
    oracle = EvidenceRef(
        f"oracle:{oracle_digest[:20]}",
        "deterministic_oracle",
        oracle_digest,
        "local reproduction oracle passed",
    )
    lifecycle.advance(EvidenceStage.ORACLE_PASSED, (oracle,))

    repro_digest = _digest({"oracle": oracle_digest, "instance": reproduction.get("instance")})
    reproduced = EvidenceRef(
        f"repro:{repro_digest[:20]}",
        "local_reproduction",
        repro_digest,
        "finding reproduced in an explicitly opted-in disposable local instance",
    )
    lifecycle.advance(EvidenceStage.LOCALLY_REPRODUCED, (reproduced,))
    jarvis["stage"] = lifecycle.stage.value
    jarvis["reproduction_evidence"] = [asdict(runtime), asdict(oracle), asdict(reproduced)]
    row["jarvis"] = jarvis
    _persist_reasoning_graph(
        repository=repository,
        row=row,
        lifecycle=lifecycle,
        mission_id=str(jarvis.get("mission_id") or ""),
        report_root=report_root,
    )
    return lifecycle.stage


def evaluate_report(
    validated: dict,
    target,
    authorization_decision,
    *,
    report_root: str | Path = "reports",
    model_egress_allowed: bool = True,
    local_lab_available: bool = False,
) -> dict:
    """Annotate all confirmed rows and emit a compact live-hunt Jarvis summary."""
    decisions: list[JarvisFindingDecision] = []
    for row in validated.get("vulnerabilities") or []:
        if (row.get("validation") or {}).get("verdict") != "confirmed":
            continue
        decisions.append(
            evaluate_finding(
                row,
                target,
                authorization_decision,
                report_root=report_root,
                model_egress_allowed=model_egress_allowed,
                local_lab_available=local_lab_available,
            )
        )
    summary = {
        "evaluated": len(decisions),
        "source_supported": sum(
            decision.stage is EvidenceStage.SOURCE_SUPPORTED for decision in decisions
        ),
        "escalated": sum(decision.should_escalate for decision in decisions),
        "deferred": sum(not decision.should_escalate for decision in decisions),
        "net_ev_usd": round(sum(max(0.0, decision.net_ev_usd) for decision in decisions), 2),
        "active_followups_vetoed": sum(
            not active_decision.approved
            for decision in decisions
            for active_decision in decision.active_decisions
        ),
        "missions": [decision.mission_id for decision in decisions if decision.mission_id],
    }
    validated.setdefault("scan", {})["jarvis"] = summary
    return summary


# --------------------------------------------------------------------------------------------
# Lightweight report-level Judge used by the live auto_hunt_run pipeline. This is the simple,
# deterministic seam wired into the hunt (source-review posture, fail-closed): every candidate
# row becomes a canonical AgentProposal + FindingLifecycle and is gated by ProposalPolicy, so
# anything that would autonomously use the network / change state / exceed budget is vetoed.
# The richer per-finding path (evaluate_finding, above) adds economics + persistence.
# --------------------------------------------------------------------------------------------
_ROLE_BY_ORIGIN = {
    "scanner": AgentRole.STATIC_ANALYSIS,
    "skill": AgentRole.ATTACK_SURFACE,
    "llm": AgentRole.HYPOTHESIS,
}


def _origin(row: dict) -> str:
    src = str(row.get("source") or "")
    if ":tool:" in src:
        return "scanner"
    if ":skill:" in src:
        return "skill"
    return "llm"


def source_review_authorization(scope_digest: str, *, budget_usd: float = 5.0,
                                max_requests: int = 0, max_human_minutes: float = 240.0,
                                human_approval: bool = False) -> AuthorizationEnvelope:
    """Authorization posture for local source review: NO network, NO state change, external
    model egress allowed. Anything needing more is vetoed by the Judge."""
    return AuthorizationEnvelope(
        scope_digest=scope_digest or "unknown",
        network_allowed=False, state_change_allowed=False,
        external_model_egress_allowed=True, human_approval=human_approval,
        budget=Budget(max_cost_usd=budget_usd, max_requests=max_requests,
                      max_human_minutes=max_human_minutes))


def proposal_from_row(row: dict, *, information_gain: float = 0.0) -> AgentProposal:
    """Map one hunt candidate row to a canonical read-only 'surface for human review' proposal."""
    ja = row.get("json_answer") or {}
    md = row.get("scanner_metadata") or {}
    origin = _origin(row)
    path = str(ja.get("file_path") or "")
    line = ja.get("line") or 0
    cwe = str(md.get("cwe") or ja.get("vulnerability_type") or "")
    digest = hashlib.sha256(f"{path}:{line}:{cwe}".encode()).hexdigest()[:16]
    ev = EvidenceRef(evidence_id=digest, kind="source-citation", digest=digest,
                     summary=f"{path}:{line}"[:200])
    return AgentProposal(
        role=_ROLE_BY_ORIGIN.get(origin, AgentRole.DATAFLOW),
        action="surface-source-finding-for-human-review",
        rationale=str(ja.get("summary") or cwe or "candidate")[:300],
        risk=RiskClass.READ_ONLY,
        expected_information_gain=float(information_gain or row.get("confidence") or 0.0),
        expected_cost_usd=0.0, expected_requests=0, expected_human_minutes=5.0,
        requires_network=False, requires_external_model=(origin == "llm"),
        evidence=(ev,),
        metadata={"cwe": cwe, "path": path, "line": line, "origin": origin,
                  "severity": str(row.get("severity") or "")})


def lifecycle_for(row: dict) -> FindingLifecycle:
    """Canonical evidence lifecycle for a row: CANDIDATE, advanced to SOURCE_SUPPORTED when the
    row carries a concrete source citation (file+line)."""
    ja = row.get("json_answer") or {}
    fid = hashlib.sha256(f"{ja.get('file_path')}:{ja.get('line')}".encode()).hexdigest()[:16]
    lc = FindingLifecycle(finding_id=fid, stage=EvidenceStage.CANDIDATE)
    if ja.get("file_path"):
        lc.advance(EvidenceStage.SOURCE_SUPPORTED,
                   [EvidenceRef(fid, "source-citation", fid,
                                f"{ja.get('file_path')}:{ja.get('line')}")])
    return lc


@dataclass
class JudgeOutcome:
    approved: list[dict] = field(default_factory=list)
    vetoed: list[tuple[dict, str]] = field(default_factory=list)
    decisions: list[tuple[str, bool, str]] = field(default_factory=list)

    def summary(self) -> dict:
        return {"approved": len(self.approved), "vetoed": len(self.vetoed),
                "veto_reasons": sorted({r for _, r in self.vetoed})}


def judge_findings(rows: list[dict], authorization: AuthorizationEnvelope,
                   *, policy: ProposalPolicy | None = None) -> JudgeOutcome:
    """Fail-closed ProposalPolicy Judge over hunt candidate rows: approved rows are annotated
    with their canonical proposal/lifecycle; forbidden/network/state-change/over-budget rows are
    separated with a reason. Deterministic."""
    policy = policy or ProposalPolicy()
    out = JudgeOutcome()
    for row in rows:
        gain = float(row.get("confidence") or 0.0)
        proposal = proposal_from_row(row, information_gain=gain)
        decision: Decision = policy.evaluate(proposal, authorization)
        out.decisions.append((proposal.proposal_id, decision.approved, decision.reason))
        if decision.approved:
            lc = lifecycle_for(row)
            out.approved.append({**row, "jarvis": {
                "proposal_id": proposal.proposal_id, "role": proposal.role.value,
                "stage": lc.stage.value, "risk": proposal.risk.value,
                "information_gain": proposal.expected_information_gain}})
        else:
            out.vetoed.append((row, decision.reason))
    return out
