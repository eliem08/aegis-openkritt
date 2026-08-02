"""Triage: normalise, deduplicate, score (Master Prompt §7–§8).

Candidates with reproducible evidence (a canary + an interaction trace) are
promoted to canonical :class:`Finding` records, deduplicated by fingerprint and
prioritised by the risk function. Candidates *without* reproducible evidence are
returned separately as hypotheses — never reported as findings (§7).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aegis.model import (
    Candidate,
    EvidenceBundle,
    Finding,
    FindingStatus,
    priority_score,
    ssvc_decision,
)

VERIFIED_CONFIDENCE_THRESHOLD = 0.5


@dataclass
class TriageResult:
    findings: list[Finding] = field(default_factory=list)
    hypotheses: list[Candidate] = field(default_factory=list)


def _promote(candidate: Candidate, evidence: EvidenceBundle | None) -> Finding:
    data = candidate.model_dump()
    priority = priority_score(candidate)
    verified = (
        evidence is not None
        and evidence.is_reproducible
        and candidate.confidence >= VERIFIED_CONFIDENCE_THRESHOLD
    )
    finding = Finding(
        **data,
        request_sequence=evidence.request_sequence() if evidence else [],
        exploit_proof_ref=evidence.evidence_id if evidence else None,
        duplicate_family=candidate.fingerprint(),
        priority=priority,
        ssvc=ssvc_decision(priority),
        status=FindingStatus.VERIFIED if verified else FindingStatus.CANDIDATE,
    )
    return finding


def triage(
    candidates: list[Candidate],
    evidence_by_id: dict[str, EvidenceBundle] | None = None,
) -> TriageResult:
    evidence_by_id = evidence_by_id or {}
    result = TriageResult()

    # Split reproducible candidates (findings) from hypotheses (§7).
    findable: list[Candidate] = []
    for candidate in candidates:
        ev = evidence_by_id.get(candidate.evidence_id) if candidate.evidence_id else None
        if ev is not None and ev.is_reproducible:
            findable.append(candidate)
        else:
            result.hypotheses.append(candidate)

    # Deduplicate findables by fingerprint; keep the highest-confidence member
    # as the representative and count the family size.
    families: dict[str, list[Candidate]] = {}
    for candidate in findable:
        families.setdefault(candidate.fingerprint(), []).append(candidate)

    for fingerprint, members in families.items():
        members.sort(key=lambda c: c.confidence, reverse=True)
        representative = members[0]
        ev = evidence_by_id.get(representative.evidence_id) if representative.evidence_id else None
        finding = _promote(representative, ev)
        finding.duplicate_count = len(members)
        result.findings.append(finding)

    # Highest priority first.
    result.findings.sort(key=lambda f: f.priority, reverse=True)
    return result
