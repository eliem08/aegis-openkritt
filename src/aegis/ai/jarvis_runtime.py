"""Canonical Jarvis seam for the live hunt pipeline.

This module intentionally does not create another agent framework. It adapts the
existing validator, hostile triager and local reproducer into ``agentic_os``'s
canonical proposal/evidence/lifecycle model, and adds a deterministic economics
portfolio gate before expensive council work.

No network or state-changing action is executed here. Active/tier-3 work is only
represented as proposals and remains subject to ``ProposalPolicy`` plus the caller's
explicit authorization envelope.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from typing import Iterable

from .agentic_os import (
    AgentProposal,
    AgentRole,
    AuthorizationEnvelope,
    Budget,
    EvidenceRef,
    EvidenceStage,
    FindingLifecycle,
    ProposalPolicy,
    RiskClass,
)
from .economics import estimate


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def _bounded(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return min(high, max(low, float(value)))


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)) or default)
    except ValueError:
        return default


def source_review_authorization(scope_digest: str = "") -> AuthorizationEnvelope:
    return AuthorizationEnvelope(
        scope_digest=scope_digest or "source-review",
        network_allowed=False,
        state_change_allowed=False,
        external_model_egress_allowed=False,
        human_approval=False,
        budget=Budget(
            max_cost_usd=_env_float("AEGIS_JARVIS_SOURCE_BUDGET_USD", 25.0),
            max_requests=0,
            max_human_minutes=_env_float("AEGIS_JARVIS_HUMAN_MINUTES", 30.0),
        ),
    )


def _evidence(kind: str, payload, summary: str) -> EvidenceRef:
    digest = _digest(payload)
    return EvidenceRef(
        evidence_id=f"ev1:{kind}:{digest[:24]}", kind=kind, digest=digest,
        summary=summary[:240],
    )


def _finding_id(row: dict) -> str:
    answer = row.get("json_answer") or {}
    material = {"file": answer.get("file_path"), "line": answer.get("line"),
                "weakness": answer.get("vulnerability_type"), "summary": answer.get("summary")}
    return f"finding:{_digest(material)[:24]}"


def _jarvis(row: dict) -> dict:
    return row.setdefault("jarvis", {})


def annotate_source_validation(row: dict, *, scope_digest: str = "") -> dict:
    validation = row.get("validation") or {}
    verdict = str(validation.get("verdict") or "unresolved")
    state = _jarvis(row)
    state["finding_id"] = _finding_id(row)
    state["validation_verdict"] = verdict
    state["stage"] = EvidenceStage.CANDIDATE.value
    if verdict != "confirmed":
        return state
    evidence = _evidence("source-validation", validation,
                         str(validation.get("reason") or "source citations validated"))
    proposal = AgentProposal(
        role=AgentRole.EVIDENCE, action="promote_source_supported",
        rationale="citation validator matched the claim to pinned source evidence",
        risk=RiskClass.OFFLINE,
        expected_information_gain=_bounded(float(validation.get("confidence") or 0.5)),
        evidence=(evidence,), metadata={"finding_id": state["finding_id"]},
    )
    decision = ProposalPolicy().evaluate(proposal, source_review_authorization(scope_digest))
    state["proposal"] = {"id": proposal.proposal_id, "role": proposal.role.value,
                         "action": proposal.action, "risk": proposal.risk.value}
    state["policy"] = asdict(decision)
    if decision.approved:
        lifecycle = FindingLifecycle(state["finding_id"])
        lifecycle.advance(EvidenceStage.SOURCE_SUPPORTED, [evidence])
        state["stage"] = lifecycle.stage.value
        state["evidence"] = [e.evidence_id for e in lifecycle.evidence]
    return state


@dataclass(frozen=True)
class FindingEconomics:
    expected_gross_usd: float
    expected_net_usd: float
    duplicate_probability: float
    review_cost_usd: float
    validation_cost_usd: float
    priority: str
    score: float

    def as_dict(self) -> dict:
        return asdict(self)


def estimate_finding_economics(row: dict, *, handle: str = "") -> FindingEconomics:
    answer = row.get("json_answer") or {}
    bounty = estimate(
        vuln_type=str(answer.get("vulnerability_type") or ""),
        severity=str(answer.get("severity") or row.get("severity") or "medium"),
        handle=handle, agreement=int(row.get("agreement", 1) or 1),
        samples=int(row.get("samples", 1) or 1),
    )
    validation = row.get("validation") or {}
    source_conf = _bounded(float(validation.get("confidence") or 0.5))
    duplicate = _bounded(float(row.get("duplicate_probability")
        or (row.get("enrichment") or {}).get("duplicate_probability")
        or _env_float("AEGIS_JARVIS_DUPLICATE_PRIOR", 0.25)))
    validation_cost = max(0.0, _env_float("AEGIS_JARVIS_VALIDATION_COST_USD", 0.05))
    review_cost = max(0.0, _env_float("AEGIS_JARVIS_COUNCIL_COST_USD", 0.10))
    expected_gross = float(bounty.expected_gain) * source_conf * (1.0 - duplicate)
    expected_net = expected_gross - validation_cost - review_cost
    min_net = _env_float("AEGIS_JARVIS_MIN_FINDING_NET_EV", 1.0)
    chainable = bool((row.get("enrichment") or {}).get("chain_required") or row.get("chainable"))
    if expected_net >= min_net:
        priority = "promote"
    elif chainable or expected_net > 0:
        priority = "retain_cheap"
    else:
        priority = "prune"
    novelty = _bounded(float(row.get("novelty_score") or 0.0))
    score = expected_net + novelty * _env_float("AEGIS_JARVIS_EXPLORATION_BONUS_USD", 5.0)
    return FindingEconomics(round(expected_gross, 4), round(expected_net, 4), round(duplicate, 4),
                            round(review_cost, 4), round(validation_cost, 4), priority,
                            round(score, 4))


def prioritize_council(rows: Iterable[dict], *, handle: str = "") -> tuple[list[dict], list[dict]]:
    promoted: list[dict] = []
    deferred: list[dict] = []
    for row in rows:
        econ = estimate_finding_economics(row, handle=handle)
        _jarvis(row)["economics"] = econ.as_dict()
        (promoted if econ.priority == "promote" else deferred).append(row)
    promoted.sort(key=lambda row: -float((_jarvis(row).get("economics") or {}).get("score", 0)))
    cap = max(1, int(_env_float("AEGIS_JARVIS_COUNCIL_MAX_FINDINGS", 12)))
    overflow = promoted[cap:]
    for row in overflow:
        _jarvis(row)["economics"]["priority"] = "retain_cheap"
    return promoted[:cap], deferred + overflow


def annotate_skeptic(row: dict) -> dict:
    triage = row.get("triage") or {}
    state = _jarvis(row)
    verdict = str(triage.get("verdict") or "unreviewed")
    state.setdefault("council", {})["skeptic"] = {
        "verdict": verdict, "reason": str(triage.get("reason") or "")[:300],
        "scope_ok": triage.get("scope_ok"),
        "attacker_realistic": triage.get("attacker_realistic"),
    }
    return state


def annotate_reproduction(row: dict) -> dict:
    repro = row.get("reproduction") or {}
    state = _jarvis(row)
    if str(repro.get("verdict") or "") != "reproduced":
        state.setdefault("council", {})["reproduction"] = {
            "verdict": str(repro.get("verdict") or "not_attempted"),
            "summary": str(repro.get("summary") or "")[:300],
        }
        return state
    if state.get("stage") != EvidenceStage.SOURCE_SUPPORTED.value:
        return state
    lifecycle = FindingLifecycle(state.get("finding_id") or _finding_id(row))
    lifecycle.advance(EvidenceStage.SOURCE_SUPPORTED,
                      [_evidence("source-validation", row.get("validation") or {}, "source supported")])
    lifecycle.advance(EvidenceStage.RUNTIME_OBSERVED,
                      [_evidence("runtime-observation", repro, "local runtime observation")])
    lifecycle.advance(EvidenceStage.ORACLE_PASSED,
                      [_evidence("reproduction-oracle", repro, "deterministic local oracle passed")])
    lifecycle.advance(EvidenceStage.LOCALLY_REPRODUCED,
                      [_evidence("local-reproduction", repro,
                                 str(repro.get("summary") or "reproduced"))])
    state["stage"] = lifecycle.stage.value
    state["evidence"] = [e.evidence_id for e in lifecycle.evidence]
    state.setdefault("council", {})["reproduction"] = {
        "verdict": "reproduced", "summary": str(repro.get("summary") or "")[:300]}
    return state


def active_tier3_proposal(action: str, *, rationale: str, expected_requests: int = 1,
                          state_change: bool = False) -> AgentProposal:
    return AgentProposal(
        role=AgentRole.API, action=action, rationale=rationale,
        risk=RiskClass.CONTROLLED_STATE_CHANGE if state_change else RiskClass.READ_ONLY,
        expected_information_gain=0.7, expected_requests=max(1, expected_requests),
        requires_network=True, metadata={"tier": 3, "active_module": True},
    )


def tier3_proposals() -> tuple[AgentProposal, ...]:
    """Register the real ``aegis.active`` capability families without executing them."""
    import aegis.active as active

    # Attribute checks intentionally fail loudly in development if Phase-3 modules drift away
    # from the canonical registry. Merely referencing these functions has no network effect.
    capabilities = (
        ("active.route_enumeration", active.run_route_stage, "bounded route enumeration", 8),
        ("active.parameter_discovery", active.run_parameter_stage, "bounded parameter discovery", 8),
        ("active.ssrf_probe", active.run_ssrf_probes, "controlled SSRF hypothesis validation", 4),
        ("active.graphql_analysis", active.analyze_graphql, "GraphQL response differential analysis", 2),
        ("active.path_normalization", active.analyze_path_normalization,
         "path-normalization differential analysis", 4),
        ("active.http_hardening", active.analyze_response_hardening,
         "HTTP security posture observation", 2),
    )
    return tuple(active_tier3_proposal(name, rationale=description, expected_requests=requests)
                 for name, _callable, description, requests in capabilities)


def evaluate_tier3_source_review() -> list[tuple[AgentProposal, object]]:
    """Proof that every registered active capability is vetoed in source-review mode."""
    policy = ProposalPolicy()
    auth = source_review_authorization()
    return [(proposal, policy.evaluate(proposal, auth)) for proposal in tier3_proposals()]
