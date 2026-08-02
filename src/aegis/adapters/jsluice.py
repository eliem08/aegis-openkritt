"""jsluice adapter — AST-based JavaScript analysis (Phase 2 §jsluice adapter).

Parses JavaScript that the scoped pipeline already acquired, using the tool's AST
analysis rather than regex scraping, and emits endpoints, parameters, and secret
*candidates* with source location and surrounding context.

Two rules keep this honest:

* **Generic high-false-positive secret matchers are off by default.** A bare
  ``token``/``apiKey``/``secret`` string match is noise; only specific, structured
  matchers (and explicitly approved custom ones, each with an identifier and
  severity) are enabled.
* **A secret candidate is never a finding.** Every emission is marked unverified
  with sub-1.0 confidence; promoting one requires the evidence pipeline and the
  sensitive-data policy, and the coordinator quarantines the task meanwhile.

This adapter reads files and makes no network requests of its own.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .base import JsonLinesAdapter, SchemaMismatch
from .contract import AdapterManifest, CapabilityTier, EventKind, ExecutionEnvelope

JSLUICE_MANIFEST = AdapterManifest(
    name="jsluice",
    version="0.0.3",
    executable_digest="",          # pin the release digest before distribution
    license="MIT",
    capability_tier=CapabilityTier.PASSIVE_DISCOVERY.value,
    input_schema_version=1,
    output_schema_version=1,
    network_profile="passive-provider",   # reads acquired files; issues no requests
)

#: Matchers that fire on any high-entropy or generically named string. Disabled by
#: default — they generate far more noise than signal.
GENERIC_MATCHERS = frozenset({
    "generic-api-key", "generic-secret", "high-entropy-string", "generic-token", "generic-password",
})

MODE_URLS = "urls"
MODE_SECRETS = "secrets"


@dataclass(frozen=True)
class CustomMatcher:
    """An operator-approved matcher. Identifier and severity are mandatory."""

    identifier: str
    pattern: str
    severity: str = "medium"

    def __post_init__(self) -> None:
        if not self.identifier or not self.pattern:
            raise ValueError("custom matchers require an identifier and a pattern")
        if self.severity not in ("low", "medium", "high", "critical"):
            raise ValueError(f"invalid severity: {self.severity}")


@dataclass(frozen=True)
class JsluiceConfig:
    mode: str = MODE_URLS
    enable_generic_matchers: bool = False
    custom_matchers: tuple[CustomMatcher, ...] = field(default_factory=tuple)
    max_results: int = 2000
    context_chars: int = 120


class JsluiceAdapter(JsonLinesAdapter):
    manifest = JSLUICE_MANIFEST
    tool_name = "jsluice"

    def __init__(self, executable=None, *, config: JsluiceConfig | None = None, **kw) -> None:
        super().__init__(executable, **kw)
        self.config = config or JsluiceConfig()
        if self.config.mode not in (MODE_URLS, MODE_SECRETS):
            raise ValueError(f"jsluice mode must be {MODE_URLS!r} or {MODE_SECRETS!r}")
        self._endpoints = 0
        self._candidates = 0
        self._suppressed = 0

    def build_command(self, envelope: ExecutionEnvelope) -> list[str]:
        cfg = self.config
        # Inputs are files the scoped pipeline already fetched, not URLs to fetch.
        argv = [self.resolve_executable(), cfg.mode, "--json"]
        for matcher in cfg.custom_matchers:
            argv += ["--patterns", f"{matcher.identifier}={matcher.pattern}"]
        argv.append(envelope.input_hash or "acquired-js")
        return argv

    def map_record(self, record: dict, envelope: ExecutionEnvelope):
        if self.config.mode == MODE_SECRETS:
            return self._map_secret(record, envelope)
        return self._map_url(record, envelope)

    # -- endpoints ---------------------------------------------------------

    def _map_url(self, record: dict, envelope: ExecutionEnvelope):
        url = record.get("url")
        if not url:
            raise SchemaMismatch("jsluice url record has no 'url' field")
        if self._endpoints >= self.config.max_results:
            return None
        self._endpoints += 1

        url = str(url)
        parts = urlsplit(url if "//" in url else f"//{url}")
        host = (parts.hostname or "").lower() or envelope.target
        params = [
            {"name": str(name), "location": "query"}
            for name in (record.get("queryParams") or record.get("query_params") or [])
        ]
        for name in record.get("bodyParams") or record.get("body_params") or []:
            params.append({"name": str(name), "location": "body"})

        data = {
            "method": str(record.get("method") or "GET").upper(),
            "path": parts.path or "/",
            "host": host,
            "url": url,
            "parameters": params,
            # Where in the source this came from — the point of AST analysis.
            "discovery_source": record.get("type") or "javascript",
            "source_file": record.get("filename") or record.get("source") or "",
        }
        if record.get("line") is not None:
            data["source_line"] = record["line"]
        # A URL assembled from variables is a weaker signal than a literal one.
        confidence = 0.6 if record.get("type") in ("assignment", "concatenation") else 1.0
        return (EventKind.ROUTE, data, confidence)

    # -- secret candidates -------------------------------------------------

    def _map_secret(self, record: dict, envelope: ExecutionEnvelope):
        kind = record.get("kind")
        if not kind:
            raise SchemaMismatch("jsluice secret record has no 'kind' field")
        kind = str(kind)

        approved = {m.identifier: m for m in self.config.custom_matchers}
        if kind in GENERIC_MATCHERS and not self.config.enable_generic_matchers:
            self._suppressed += 1
            return None  # noisy generic matcher, disabled by default

        self._candidates += 1
        severity = approved[kind].severity if kind in approved else str(record.get("severity") or "medium")
        context = record.get("context")
        if isinstance(context, str):
            context = context[: self.config.context_chars]
        data = {
            "kind_hint": kind,
            "severity": severity,
            "matcher": "custom" if kind in approved else "builtin",
            "source_file": record.get("filename") or "",
            "source_line": record.get("line"),
            "context": context,
            # Never a finding: promotion requires the evidence pipeline + policy.
            "verified": False,
        }
        # Deliberately sub-1.0: a candidate is a lead, not proof.
        return (EventKind.SECRET_CANDIDATE, data, 0.5)

    def interpret_result(self, result, envelope: ExecutionEnvelope):
        event = super().interpret_result(result, envelope)
        event.data.update({
            "mode": self.config.mode,
            "endpoints": self._endpoints,
            "secret_candidates": self._candidates,
            "suppressed_generic_matches": self._suppressed,
        })
        return event
