"""Supply-chain policy — SBOM, image pinning, and severity gating (Phase 5)."""

from .supplychain import (
    COPYLEFT_LICENSES,
    SBOM,
    Component,
    PolicyException,
    PolicyResult,
    Severity,
    SeverityPolicy,
    UnpinnedImage,
    Vulnerability,
    generate_sbom,
    verify_image_pin,
)

__all__ = [
    "COPYLEFT_LICENSES",
    "SBOM",
    "Component",
    "PolicyException",
    "PolicyResult",
    "Severity",
    "SeverityPolicy",
    "UnpinnedImage",
    "Vulnerability",
    "generate_sbom",
    "verify_image_pin",
]
