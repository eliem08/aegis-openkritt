"""Canonical Jarvis seam for the live hunt pipeline.

This module intentionally does not create another agent framework. It adapts the existing
validator, hostile triager and local reproducer into ``agentic_os``'s canonical proposal,
evidence and lifecycle model; applies deterministic finding-level economics; and registers
dormant Phase-3 capabilities as proposals rather than executing them.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
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


def _authorization_context(repository: str) -> dict:
    """Read already-verified program context; never turns a blocked target into an allowed one."""
    if not repository:
        return {}
    try:
        from .target_authorization import AuthorizationLedger
        record = AuthorizationLedger().get(repository)
    except Exception:
        record = None
    if record is None or record.status != "authorized":
        return {}
    return {
        "repository": repository,
        "program_id": record.program_id,
        "source_platform": record.source_platform,
        "scope_digest": record.scope_snapshot_hash,
        "bounty_eligible": bool(record.bounty_eligible),
    }


def annotate_source_validation(row: dict, *, scope_digest: str = "",
                               repository: str = "") -> dict:
    validation = row.get("validation") or {}
    verdict = str(validation.get("verdict") or "unresolved")
    state = _jarvis(row)
    state["finding_id"] = _finding_id(row)
    state["validation_verdict"] = verdict
    state["stage"] = EvidenceStage.CANDIDATE.value
    context = _authorization_context(repository)
    state.update({k: v for k, v in context.items() if v not in (None, "")})
    scope_digest = scope_digest or str(context.get("scope_digest") or "source-review")
    if verdict != "confirmed":
        _persist(row, repository=repository, scope_digest=scope_digest)
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
    _persist(row, repository=repository, scope_digest=scope_digest)
    return state


@dataclass(frozen=True)
class FindingEconomics:
    expected_gross_usd: float
    expected_net_usd: float
    duplicate_probability: float
    review_cost_usd: float
    validation_cost_usd: float
    acceptance_probability: float
    uniqueness_probability: float
    prior_samples: int
    priority: str
    score: float

    def as_dict(self) -> dict:
        return asdict(self)


def _learned(row: dict, weakness: str, handle: str) -> dict:
    state = _jarvis(row)
    program_id = handle or str(state.get("program_id") or "")
    if not program_id:
        return {"samples": 0, "acceptance": 0.5, "uniqueness": 0.5,
                "mean_payout_usd": 0.0, "mean_cost_usd": 0.0}
    try:
        from .jarvis_persistence import learned_probabilities, state_db_path
        db = Path(state_db_path())
        if not db.is_file():
            raise FileNotFoundError
        return learned_probabilities(program_id, weakness)
    except Exception:
        return {"samples": 0, "acceptance": 0.5, "uniqueness": 0.5,
                "mean_payout_usd": 0.0, "mean_cost_usd": 0.0}


def estimate_finding_economics(row: dict, *, handle: str = "") -> FindingEconomics:
    answer = row.get("json_answer") or {}
    weakness = str(answer.get("vulnerability_type") or "unspecified")
    bounty = estimate(
        vuln_type=weakness,
        severity=str(answer.get("severity") or row.get("severity") or "medium"),
        handle=handle or str(_jarvis(row).get("program_id") or ""),
        agreement=int(row.get("agreement", 1) or 1),
        samples=int(row.get("samples", 1) or 1),
    )
    validation = row.get("validation") or {}
    source_conf = _bounded(float(validation.get("confidence") or 0.5))
    learned = _learned(row, weakness, handle)
    prior_samples = int(learned.get("samples") or 0)
    # Shrink sparse outcomes to the neutral model; at >=20 outcomes the empirical signal
    # carries most of the weight. This prevents one lucky/duplicate report from hijacking EV.
    learned_weight = min(0.8, prior_samples / 25.0)
    acceptance = ((1.0 - learned_weight) * 0.60
                  + learned_weight * _bounded(float(learned.get("acceptance") or 0.5)))
    uniqueness = ((1.0 - learned_weight) * 0.75
                  + learned_weight * _bounded(float(learned.get("uniqueness") or 0.5)))
    explicit_duplicate = row.get("duplicate_probability")
    if explicit_duplicate is None:
        explicit_duplicate = (row.get("enrichment") or {}).get("duplicate_probability")
    duplicate = _bounded(float(explicit_duplicate)) if explicit_duplicate is not None \
        else _bounded(1.0 - uniqueness)
    validation_cost = max(0.0, _env_float("AEGIS_JARVIS_VALIDATION_COST_USD", 0.05))
    review_cost = max(0.0, _env_float("AEGIS_JARVIS_COUNCIL_COST_USD", 0.10))
    learned_cost = max(0.0, float(learned.get("mean_cost_usd") or 0.0))
    if prior_samples:
        review_cost = max(review_cost, min(learned_cost, 100.0))
    payout_basis = float(bounty.likely_bounty)
    learned_payout = float(learned.get("mean_payout_usd") or 0.0)
    if learned_payout > 0 and prior_samples:
        payout_basis = (1.0 - learned_weight) * payout_basis + learned_weight * learned_payout
    expected_gross = payout_basis * source_conf * acceptance * (1.0 - duplicate)
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
    return FindingEconomics(
        round(expected_gross, 4), round(expected_net, 4), round(duplicate, 4),
        round(review_cost, 4), round(validation_cost, 4), round(acceptance, 4),
        round(1.0 - duplicate, 4), prior_samples, priority, round(score, 4))


def prioritize_council(rows: Iterable[dict], *, handle: str = "") -> tuple[list[dict], list[dict]]:
    promoted: list[dict] = []
    deferred: list[dict] = []
    for row in rows:
        econ = estimate_finding_economics(row, handle=handle)
        _jarvis(row)["economics"] = econ.as_dict()
        _persist(row, repository=str(_jarvis(row).get("repository") or ""),
                 scope_digest=str(_jarvis(row).get("scope_digest") or ""))
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
    state.setdefault("council", {})["skeptic"] = {
        "verdict": str(triage.get("verdict") or "unreviewed"),
        "reason": str(triage.get("reason") or "")[:300],
        "scope_ok": triage.get("scope_ok"),
        "attacker_realistic": triage.get("attacker_realistic"),
    }
    _persist(row, repository=str(state.get("repository") or ""),
             scope_digest=str(state.get("scope_digest") or ""))
    return state


def annotate_reproduction(row: dict) -> dict:
    repro = row.get("reproduction") or {}
    state = _jarvis(row)
    if str(repro.get("verdict") or "") != "reproduced":
        state.setdefault("council", {})["reproduction"] = {
            "verdict": str(repro.get("verdict") or "not_attempted"),
            "summary": str(repro.get("summary") or "")[:300],
        }
        _persist(row, repository=str(state.get("repository") or ""),
                 scope_digest=str(state.get("scope_digest") or ""))
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
    _persist(row, repository=str(state.get("repository") or ""),
             scope_digest=str(state.get("scope_digest") or ""))
    return state


def _persist(row: dict, *, repository: str, scope_digest: str) -> None:
    try:
        from .jarvis_persistence import persist_finding
        persist_finding(row, repository=repository, scope_digest=scope_digest)
    except Exception as exc:
        _jarvis(row)["persistence_error"] = type(exc).__name__


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
    policy = ProposalPolicy()
    auth = source_review_authorization()
    return [(proposal, policy.evaluate(proposal, auth)) for proposal in tier3_proposals()]
