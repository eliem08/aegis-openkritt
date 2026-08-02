"""Submission quality gates (Master Prompt §7–§8; P1 #27, #29).

Only reproducible, verified, in-scope, materially-impactful, redacted,
non-duplicate findings are submittable. Anything else is held back — never
submit scanner guesses or hypotheses.
"""

from __future__ import annotations

from dataclasses import dataclass

from aegis.model import EvidenceBundle, Finding, FindingStatus

VERIFIED_STATES = {FindingStatus.VERIFIED, FindingStatus.PATCHED, FindingStatus.VERIFIED_FIXED}


@dataclass
class QualityGate:
    name: str
    passed: bool
    detail: str = ""


def evaluate_quality(
    finding: Finding,
    evidence: EvidenceBundle | None = None,
    *,
    in_scope: bool = True,
    redacted: bool = True,
    is_duplicate: bool = False,
    min_priority: float = 0.0,
) -> list[QualityGate]:
    reproducible = evidence is not None and evidence.is_reproducible
    return [
        QualityGate("reproducible", reproducible, "requires a canary + interaction trace"),
        QualityGate("verified", finding.status in VERIFIED_STATES, "not a hypothesis / guess"),
        QualityGate("in_scope", in_scope, "target within signed scope"),
        QualityGate("material_impact", finding.priority > min_priority, "priority above threshold"),
        QualityGate("redacted", redacted, "credentials/PII removed from evidence"),
        QualityGate("not_duplicate", not is_duplicate, "no internal/public match"),
    ]


def is_submittable(gates: list[QualityGate]) -> bool:
    return all(g.passed for g in gates)


def failed_gates(gates: list[QualityGate]) -> list[QualityGate]:
    return [g for g in gates if not g.passed]
