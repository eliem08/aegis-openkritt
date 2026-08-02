"""Acceptance-grade reporting: redact -> dedup -> quality gates -> report (§11).

The path from a verified finding to a submission-ready, human-approved report.
"""

from .dedup import DuplicateResult, is_duplicate
from .pipeline import SubmissionPackage, prepare_submission
from .quality import QualityGate, evaluate_quality, failed_gates, is_submittable
from .redact import redact, redact_evidence
from .report import REMEDIATION, SubmissionReport, build_report

__all__ = [
    "redact",
    "redact_evidence",
    "SubmissionReport",
    "build_report",
    "REMEDIATION",
    "QualityGate",
    "evaluate_quality",
    "is_submittable",
    "failed_gates",
    "DuplicateResult",
    "is_duplicate",
    "SubmissionPackage",
    "prepare_submission",
]
