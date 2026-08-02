"""Vulnerability detectors — the extensible "any bug class is a plug-in" layer.

Each detector runs through a scope-enforcing, per-request-gated client. Ships
high-value detectors (BOLA/IDOR, exposed files, open redirect); add a class by
writing a :class:`Detector` and registering it. Requires ``httpx``.
"""

from .access_control import BolaDetector, ObjectRef
from .base import (
    DetectionResult,
    Detector,
    DetectorContext,
    DetectorRegistry,
    GateBlocked,
    Identity,
)
from .exposure import ExposedFileDetector
from .redirects import OpenRedirectDetector
from .worker import DetectorWorker


def default_registry() -> DetectorRegistry:
    """A registry with the shipped high-value detectors."""
    reg = DetectorRegistry()
    reg.register(BolaDetector())
    reg.register(ExposedFileDetector())
    reg.register(OpenRedirectDetector())
    return reg


__all__ = [
    "Detector",
    "DetectorContext",
    "DetectorRegistry",
    "DetectionResult",
    "GateBlocked",
    "Identity",
    "BolaDetector",
    "ObjectRef",
    "ExposedFileDetector",
    "OpenRedirectDetector",
    "DetectorWorker",
    "default_registry",
]
