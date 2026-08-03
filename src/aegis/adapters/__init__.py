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
    JsonDocumentAdapter,
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
    DocumentAdapter,
    EnvelopeError,
    EnvelopeLimits,
    EventKind,
    ExecutionEnvelope,
    event_from,
    validate_against_manifest,
)
from .dalfox import (
    DALFOX_MANIFEST,
    DalfoxAdapter,
    DalfoxConfig,
    DalfoxMode,
    DalfoxOutcome,
    DangerousModeNotAuthorized,
)
from .fake import FAKE_MANIFEST, FakeDiscoveryAdapter
from .gau import GAU_MANIFEST, GauAdapter, GauConfig
from .http_probe import HTTP_PROBE_MANIFEST, HttpProbeAdapter, HttpProbeConfig
from .jsluice import JSLUICE_MANIFEST, CustomMatcher, JsluiceAdapter, JsluiceConfig
from .katana import KATANA_MANIFEST, HeadlessNotPermitted, KatanaAdapter, KatanaConfig
from .nuclei import (
    DEFAULT_ALLOWED_PROTOCOLS,
    PROHIBITED_PROTOCOLS,
    ManifestError,
    NucleiAdapter,
    NucleiConfig,
    RejectReason,
    TemplateEntry,
    TemplateManifest,
    TemplateVerdict,
    new_template_manifest,
    sign_manifest,
)
from .repository_scanners import (
    GITLEAKS_MANIFEST,
    OSV_SCANNER_MANIFEST,
    SEMGREP_MANIFEST,
    SOURCE_SCANNER_MANIFESTS,
    GitleaksDocumentAdapter,
    OsvScannerDocumentAdapter,
    SemgrepDocumentAdapter,
    source_scanner_parsers,
)
from .subfinder import SUBFINDER_MANIFEST, SubfinderAdapter, SubfinderConfig

#: The Phase 2 discovery set, in stage order.
DISCOVERY_MANIFESTS = (
    SUBFINDER_MANIFEST, GAU_MANIFEST, HTTP_PROBE_MANIFEST, KATANA_MANIFEST, JSLUICE_MANIFEST,
)


def discovery_adapters(pins=None, **kwargs) -> dict:
    """Registry of the five discovery adapters, keyed by manifest name.

    ``pins`` is a ``{tool_name: PinnedTool}`` mapping (from ``aegis.tools.pin``);
    when given, each adapter is constructed with its pinned digest so it verifies
    the on-disk binary. Without pins, the adapters keep the code-shipped empty
    digest and fail closed.
    """
    classes = [SubfinderAdapter, GauAdapter, HttpProbeAdapter, KatanaAdapter, JsluiceAdapter]
    adapters = []
    for cls in classes:
        digest = None
        if pins is not None:
            entry = pins.get(cls.tool_name)
            digest = entry.sha256 if entry is not None else None
        adapters.append(cls(digest=digest, **kwargs) if digest else cls(**kwargs))
    return {a.manifest.name: a for a in adapters}


__all__ = [
    "Adapter",
    "AdapterEvent",
    "AdapterManifest",
    "DocumentAdapter",
    "CapabilityTier",
    "EnvelopeError",
    "EnvelopeLimits",
    "EventKind",
    "ExecutionEnvelope",
    "event_from",
    "validate_against_manifest",
    "FakeDiscoveryAdapter",
    "FAKE_MANIFEST",
    "JsonDocumentAdapter",
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
    "NucleiAdapter",
    "NucleiConfig",
    "TemplateManifest",
    "TemplateEntry",
    "TemplateVerdict",
    "ManifestError",
    "RejectReason",
    "new_template_manifest",
    "sign_manifest",
    "DEFAULT_ALLOWED_PROTOCOLS",
    "PROHIBITED_PROTOCOLS",
    "DalfoxAdapter",
    "DalfoxConfig",
    "DalfoxMode",
    "DalfoxOutcome",
    "DangerousModeNotAuthorized",
    "DALFOX_MANIFEST",
    "SemgrepDocumentAdapter",
    "GitleaksDocumentAdapter",
    "OsvScannerDocumentAdapter",
    "SEMGREP_MANIFEST",
    "GITLEAKS_MANIFEST",
    "OSV_SCANNER_MANIFEST",
    "SOURCE_SCANNER_MANIFESTS",
    "source_scanner_parsers",
]
