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
    "build_console",
    "SubmissionPackage",
    "prepare_submission",
    "resolve_in_scope",
]
