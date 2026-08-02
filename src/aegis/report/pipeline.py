"""End-to-end submission preparation (P1 #22–#29).

finding + evidence -> redact -> dedup -> quality gates -> report. The result is
a :class:`SubmissionPackage` that says whether it is submittable and why not.
Submission itself stays human-approved (§10, P1 #28) — this prepares, it does
not send.
"""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel, Field

from aegis.model import EvidenceBundle, Finding

from .dedup import DuplicateResult, is_duplicate
from .quality import QualityGate, evaluate_quality, failed_gates, is_submittable
from .redact import redact_evidence
from .report import SubmissionReport, build_report


class SubmissionPackage(BaseModel):
    report: SubmissionReport
    markdown: str
    submittable: bool
    duplicate: bool
    duplicate_of: list[tuple[str, str]] = Field(default_factory=list)
    gate_results: list[dict] = Field(default_factory=list)
    blocking_reasons: list[str] = Field(default_factory=list)


def prepare_submission(
    finding: Finding,
    evidence: EvidenceBundle | None = None,
    *,
    program_handle: str | None = None,
    in_scope: bool = True,
    prior_findings: Iterable[Finding] | None = None,
    corpus: Iterable | None = None,
    min_priority: float = 0.0,
) -> SubmissionPackage:
    redacted_evidence = redact_evidence(evidence) if evidence is not None else None

    dup: DuplicateResult = is_duplicate(finding, prior_findings=prior_findings, corpus=corpus)

    gates: list[QualityGate] = evaluate_quality(
        finding,
        redacted_evidence,
        in_scope=in_scope,
        redacted=True,
        is_duplicate=dup.is_duplicate,
        min_priority=min_priority,
    )

    report = build_report(
        finding, redacted_evidence, program_handle=program_handle, redact=False
    )

    return SubmissionPackage(
        report=report,
        markdown=report.to_markdown(),
        submittable=is_submittable(gates),
        duplicate=dup.is_duplicate,
        duplicate_of=dup.matches,
        gate_results=[{"name": g.name, "passed": g.passed, "detail": g.detail} for g in gates],
        blocking_reasons=[g.name for g in failed_gates(gates)],
    )
