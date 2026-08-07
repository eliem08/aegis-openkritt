"""Acceptance-grade reporting: redact -> dedup -> quality gates -> report (§11).

The path from a verified finding to a submission-ready, human-approved report.
"""

from .console import build_console
from .dedup import DuplicateResult, is_duplicate
from .pipeline import SubmissionPackage, prepare_submission, resolve_in_scope
from .quality import QualityGate, evaluate_quality, failed_gates, is_submittable
from .redact import redact, redact_evidence
from .report import REMEDIATION, SubmissionReport, build_report

__all__ = [
    "REMEDIATION",
    "DuplicateResult",
    "QualityGate",
    "SubmissionPackage",
    "SubmissionReport",
    "build_console",
    "build_report",
    "evaluate_quality",
    "failed_gates",
    "is_duplicate",
    "is_submittable",
    "prepare_submission",
    "redact",
    "redact_evidence",
    "resolve_in_scope",
]
