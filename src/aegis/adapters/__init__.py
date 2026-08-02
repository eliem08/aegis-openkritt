"""Adapter contract + a fake adapter (Master Prompt §6; Phase 1).

Adapters translate an immutable ``ExecutionEnvelope`` into a bounded command and
its output into typed events. They never touch product state or repositories.
"""

from .contract import (
    Adapter,
    AdapterEvent,
    AdapterManifest,
    CapabilityTier,
    EnvelopeError,
    EnvelopeLimits,
    EventKind,
    ExecutionEnvelope,
    event_from,
    validate_against_manifest,
)
from .fake import FAKE_MANIFEST, FakeDiscoveryAdapter

__all__ = [
    "Adapter",
    "AdapterEvent",
    "AdapterManifest",
    "CapabilityTier",
    "EnvelopeError",
    "EnvelopeLimits",
    "EventKind",
    "ExecutionEnvelope",
    "event_from",
    "validate_against_manifest",
    "FakeDiscoveryAdapter",
    "FAKE_MANIFEST",
]
