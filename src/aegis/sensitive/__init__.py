"""Sensitive-data containment (Phase 4).

Classifies raw artifacts before normalization and, on a match, quarantines them
encrypted at rest — so no credential, token, key, financial datum, or direct
identifier can pass into the asset graph, an API response, or a report.
"""

from .boundary import QuarantineOutcome, SensitiveDataBoundary
from .classifier import (
    Category,
    Classification,
    ClassifierConfig,
    Match,
    Method,
    SensitiveDataClassifier,
    redact,
)

__all__ = [
    "SensitiveDataClassifier",
    "ClassifierConfig",
    "Classification",
    "Category",
    "Method",
    "Match",
    "redact",
    "SensitiveDataBoundary",
    "QuarantineOutcome",
]
