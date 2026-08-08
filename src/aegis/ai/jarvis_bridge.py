"""Canonical Jarvis bridge for the live autonomous source-review hunt.

The repository historically grew two parallel worlds: the production ``auto_hunt``
pipeline and the newer ``agentic_os``/Jarvis contracts.  This module is the single seam
between them.  It does not replace the proven hunt implementation; it normalizes each
validated finding into the canonical proposal/lifecycle/economics model and decides
whether additional expensive research is worth scheduling.

Important boundaries:
* source validation can advance only ``candidate -> source_supported``;
* scanner/LLM claims never become reproduced evidence here;
* ``active/`` follow-ups are visible to the same fail-closed ``ProposalPolicy``;
* negative-EV findings are deferred, not relabeled false positives;
* missions are durable in the Jarvis SQLite state store.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
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
    ProposalPolicy,
    RiskClass,
)
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
) -> AuthorizationEnvelope:
    """Translate target authorization into a source-review-only action envelope."""
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
        state_change_allowed=False,
        external_model_egress_allowed=bool(model_egress_allowed),
        human_approval=False,
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
        rationale="A source candidate survived citation validation and deterministic reachability checks.",
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
    values = (
        enrichment.get("bounty_likely"),
        economics.get("likely_bounty"),
        getattr(target, "likely_payout", 0.0),
    )
    for value in values:
        try:
            amount = float(value or 0.0)
        except (TypeError, ValueError):
            continue
        if amount > 0:
            return amount
    ceiling = max(0.0, float(getattr(target, "reward_ceiling", 0.0) or 0.0))
    return ceiling * 0.30


def opportunity_from_finding(row: dict, target) -> Opportunity:
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
                "Attempt bounded localhost-only reproduction with deterministic positive/negative controls."
            ),
            risk=RiskClass.OFFLINE,
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
                "Assemble immutable report-quality evidence after reproduction and independent review."
            ),
            risk=RiskClass.OFFLINE,
            expected_information_gain=0.30,
            expected_cost_usd=0.05,
            metadata={"finding_id": finding_id, "council_stage": "evidence"},
        ),
    )


def _state_path(report_root: str | Path = "reports") -> Path:
    configured = os.environ.get("AEGIS_JARVIS_STATE_DB", "").strip()
    path = Path(configured) if configured else Path(report_root) / "jarvis_state.sqlite3"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


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
    )
    policy = ProposalPolicy()
    proposal = proposal_from_validated_row(getattr(target, "repository", ""), row)
    source_decision = policy.evaluate(proposal, envelope)
    lifecycle = lifecycle_from_validated_row(getattr(target, "repository", ""), row)

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

    # ``active/`` is now on the same seam.  Source findings can suggest the appropriate live
    # validation lane, but the source-review envelope has no network/state/human authority, so
    # these decisions are expected to be vetoes until an explicit active engagement is opened.
    active = tuple(
        policy.evaluate(active_proposal, envelope)
        for active_proposal in followup_intents_for_finding(row)
    )

    mission_id = ""
    if should_escalate:
        mission_id = _persist_mission(
            lifecycle=lifecycle,
            scope_digest=envelope.scope_digest,
            repository=getattr(target, "repository", ""),
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


def evaluate_report(
    validated: dict,
    target,
    authorization_decision,
    *,
    report_root: str | Path = "reports",
    model_egress_allowed: bool = True,
    local_lab_available: bool = False,
) -> dict:
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
