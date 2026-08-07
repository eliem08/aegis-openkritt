"""Vulnerability detectors — the extensible "any bug class is a plug-in" layer.

Each detector runs through a scope-enforcing, per-request-gated client. Ships
high-value detectors (BOLA/IDOR, exposed files, open redirect); add a class by
writing a :class:`Detector` and registering it. Requires ``httpx``.
"""

from .access_control import (
    BflaDetector,
    BolaDetector,
    ObjectRef,
    ObjectSeed,
    build_bola_objects,
    route_signature,
)
from .auth import MissingAuthDetector
from .base import (
    DetectionResult,
    Detector,
    DetectorContext,
    DetectorRegistry,
    GateBlocked,
    Identity,
)
from .cors import CorsMisconfigDetector
from .cross_tenant import CrossTenantDetector, CrossTenantResource
from .exposure import ErrorDisclosureDetector, ExposedFileDetector
from .recon import ReconWorker, parse_openapi
from .redirects import OpenRedirectDetector
from .worker import DetectorWorker


def default_registry() -> DetectorRegistry:
    """A registry with the shipped high-value detectors."""
    reg = DetectorRegistry()
    reg.register(BolaDetector())
    reg.register(BflaDetector())
    reg.register(MissingAuthDetector())
    reg.register(ExposedFileDetector())
    reg.register(CorsMisconfigDetector())
    reg.register(OpenRedirectDetector())
    reg.register(ErrorDisclosureDetector())
    reg.register(CrossTenantDetector())
    return reg


__all__ = [
    "BflaDetector",
    "BolaDetector",
    "CorsMisconfigDetector",
    "CrossTenantDetector",
    "CrossTenantResource",
    "DetectionResult",
    "Detector",
    "DetectorContext",
    "DetectorRegistry",
    "DetectorWorker",
    "ErrorDisclosureDetector",
    "ExposedFileDetector",
    "GateBlocked",
    "Identity",
    "MissingAuthDetector",
    "ObjectRef",
    "ObjectSeed",
    "OpenRedirectDetector",
    "ReconWorker",
    "build_bola_objects",
    "default_registry",
    "parse_openapi",
    "route_signature",
]
