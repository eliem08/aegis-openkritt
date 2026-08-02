"""Guarded active testing (Phase 3).

Clean-room implementations of high-value active-testing behaviors — no copied
AGPL/GPL source, wordlists, or datasets. Each engine is transport-agnostic and
carries a fixed capability it cannot widen at runtime.
"""

from .parameters import (
    FORM,
    JSON,
    XML,
    DiscoveryConfig,
    DiscoveryResult,
    ParameterDiscovery,
    ParameterFinding,
    ProbeResponse,
    UnsupportedMethod,
)

__all__ = [
    "ParameterDiscovery",
    "DiscoveryConfig",
    "DiscoveryResult",
    "ParameterFinding",
    "ProbeResponse",
    "UnsupportedMethod",
    "FORM",
    "JSON",
    "XML",
]
