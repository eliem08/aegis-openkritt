"""Adapter contract, the fake adapter, and the pinned discovery adapters.

Adapters translate an immutable ``ExecutionEnvelope`` into a bounded command and
its output into typed events. They never touch product state or repositories.

The Phase 2 discovery set — subfinder, gau, http-probe, katana, jsluice — wraps
pinned third-party binaries. Each declares its license and an
``executable_digest`` that must be filled with the pinned release checksum before
distribution; until then the adapter refuses to run unless explicitly allowed.
"""

from .base import (
    GATEWAY_BLOCKED,
    PARSER_INCOMPATIBLE,
    PROVIDER_ERROR,
    QUOTA_EXHAUSTED,
    TARGET_UNREACHABLE,
    JsonLinesAdapter,
    SchemaMismatch,
    ToolUnavailable,
    in_parent_scope,
)
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
from .gau import GAU_MANIFEST, GauAdapter, GauConfig
from .http_probe import HTTP_PROBE_MANIFEST, HttpProbeAdapter, HttpProbeConfig
from .jsluice import JSLUICE_MANIFEST, CustomMatcher, JsluiceAdapter, JsluiceConfig
from .katana import KATANA_MANIFEST, HeadlessNotPermitted, KatanaAdapter, KatanaConfig
from .subfinder import SUBFINDER_MANIFEST, SubfinderAdapter, SubfinderConfig

#: The Phase 2 discovery set, in stage order.
DISCOVERY_MANIFESTS = (
    SUBFINDER_MANIFEST, GAU_MANIFEST, HTTP_PROBE_MANIFEST, KATANA_MANIFEST, JSLUICE_MANIFEST,
)


def discovery_adapters(**kwargs) -> dict:
    """Registry of the five discovery adapters, keyed by manifest name."""
    adapters = [
        SubfinderAdapter(**kwargs), GauAdapter(**kwargs), HttpProbeAdapter(**kwargs),
        KatanaAdapter(**kwargs), JsluiceAdapter(**kwargs),
    ]
    return {a.manifest.name: a for a in adapters}


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
    "JsonLinesAdapter",
    "SchemaMismatch",
    "ToolUnavailable",
    "in_parent_scope",
    "PROVIDER_ERROR",
    "TARGET_UNREACHABLE",
    "PARSER_INCOMPATIBLE",
    "QUOTA_EXHAUSTED",
    "GATEWAY_BLOCKED",
    "SubfinderAdapter",
    "SubfinderConfig",
    "SUBFINDER_MANIFEST",
    "GauAdapter",
    "GauConfig",
    "GAU_MANIFEST",
    "HttpProbeAdapter",
    "HttpProbeConfig",
    "HTTP_PROBE_MANIFEST",
    "KatanaAdapter",
    "KatanaConfig",
    "KATANA_MANIFEST",
    "HeadlessNotPermitted",
    "JsluiceAdapter",
    "JsluiceConfig",
    "CustomMatcher",
    "JSLUICE_MANIFEST",
    "DISCOVERY_MANIFESTS",
    "discovery_adapters",
]
