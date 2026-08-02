"""HTTP probe adapter over a pinned httpx release (Phase 2 §httpx adapter).

Named ``HttpProbeAdapter`` rather than ``HttpxAdapter`` to avoid colliding with
the Python ``httpx`` package that the rest of the codebase imports.

Emits one typed service observation per probed endpoint — status, addressing,
TLS, CDN/ASN, technologies, title, content type/length, response time, and stable
body/header hashes — plus vhost/websocket/redirect diagnostics as typed fields
rather than free text. Retries are bounded and always carry an explicit reason.

This is the first stage that actually touches the target, so it runs under the
``target-observation`` profile with safe methods only. The tool's service/server
mode is never enabled: it is not exposed to callers under any configuration.
"""

from __future__ import annotations

from dataclasses import dataclass

from .base import TARGET_UNREACHABLE, JsonLinesAdapter, SchemaMismatch
from .contract import AdapterManifest, CapabilityTier, EventKind, ExecutionEnvelope

HTTP_PROBE_MANIFEST = AdapterManifest(
    name="http-probe",
    version="1.6.9",               # pinned httpx release
    executable_digest="",          # pin the release digest before distribution
    license="MIT",
    capability_tier=CapabilityTier.PASSIVE_DISCOVERY.value,
    input_schema_version=1,
    output_schema_version=3,       # httpx -json record shape
    network_profile="target-observation",
)

SAFE_METHODS = ("GET", "HEAD")


@dataclass(frozen=True)
class HttpProbeConfig:
    method: str = "GET"
    retries: int = 2
    backoff_seconds: float = 1.0
    timeout_seconds: int = 10
    rate_limit_per_second: int = 5
    follow_redirects: bool = False
    max_response_bytes: int = 2 * 1024 * 1024


class HttpProbeAdapter(JsonLinesAdapter):
    manifest = HTTP_PROBE_MANIFEST
    tool_name = "httpx"

    def __init__(self, executable=None, *, config: HttpProbeConfig | None = None, **kw) -> None:
        super().__init__(executable, **kw)
        self.config = config or HttpProbeConfig()
        if self.config.method.upper() not in SAFE_METHODS:
            raise ValueError(f"probe method must be one of {SAFE_METHODS}")
        self._live = 0
        self._unreachable = 0

    def build_command(self, envelope: ExecutionEnvelope) -> list[str]:
        cfg = self.config
        argv = [
            self.resolve_executable(),
            "-json", "-silent", "-no-color",
            "-target", envelope.target,
            "-x", cfg.method.upper(),
            "-retries", str(cfg.retries),
            "-timeout", str(cfg.timeout_seconds),
            "-rate-limit", str(cfg.rate_limit_per_second),
            "-response-size-to-read", str(cfg.max_response_bytes),
            # Typed enrichment we normalize into the asset graph.
            "-status-code", "-content-length", "-content-type", "-title", "-tech-detect",
            "-ip", "-cname", "-tls-grab", "-cdn", "-asn", "-response-time", "-hash", "sha256",
            "-websocket", "-vhost",
        ]
        if cfg.follow_redirects:
            argv.append("-follow-redirects")
        return argv

    def map_record(self, record: dict, envelope: ExecutionEnvelope):
        url = record.get("url") or record.get("input")
        if not url:
            raise SchemaMismatch("http probe record has no 'url'/'input' field")

        # A failed probe is a typed diagnostic with its retry reason, not silence.
        if record.get("failed") or record.get("error"):
            self._unreachable += 1
            return (EventKind.DIAGNOSTIC, {
                "code": TARGET_UNREACHABLE,
                "message": str(record.get("error") or "probe failed"),
                "url": str(url),
                "retries": self.config.retries,
                "backoff_seconds": self.config.backoff_seconds,
                "blocking": False,
            }, 0.0)

        status = record.get("status_code")
        if status is None:
            raise SchemaMismatch("http probe record has no 'status_code'")

        host = record.get("input") or _host_of(str(url))
        port = record.get("port") or _default_port(record.get("scheme") or _scheme_of(str(url)))
        scheme = str(record.get("scheme") or _scheme_of(str(url)) or "https")
        hashes = record.get("hash") or {}

        data = {
            "url": str(url),
            "host": _host_of(str(url)) or str(host),
            "port": int(port),
            "scheme": scheme,
            "method": self.config.method.upper(),
            "status": int(status),
            "technologies": list(record.get("tech") or []),
        }
        # Optional typed fields — copied only when the tool actually reported them.
        for src, dest in (
            ("content_length", "content_length"), ("content_type", "content_type"),
            ("title", "title"), ("webserver", "webserver"), ("host", "ip"),
            ("cname", "cname"), ("cdn_name", "cdn"), ("response_time", "response_time"),
            ("websocket", "websocket"), ("vhost", "vhost"), ("location", "redirect_location"),
            ("chain_status_codes", "redirect_chain"),
        ):
            if record.get(src) not in (None, "", [], {}):
                data[dest] = record[src]
        if isinstance(record.get("asn"), dict):
            data["asn"] = record["asn"].get("as_number") or record["asn"].get("asn")
        if isinstance(record.get("tls"), dict):
            tls = record["tls"]
            data["tls"] = {k: tls[k] for k in ("tls_version", "cipher", "subject_cn", "issuer_cn")
                           if tls.get(k) not in (None, "")}
        # Stable hashes make re-probing deterministic and diffable.
        for src, dest in (("body_sha256", "body_hash"), ("header_sha256", "header_hash")):
            if isinstance(hashes, dict) and hashes.get(src):
                data[dest] = hashes[src]

        self._live += 1
        return (EventKind.SERVICE, data, 1.0)

    def interpret_result(self, result, envelope: ExecutionEnvelope):
        event = super().interpret_result(result, envelope)
        event.data.update({"live": self._live, "unreachable": self._unreachable})
        return event


def _host_of(url: str) -> str:
    from urllib.parse import urlsplit

    parts = urlsplit(url if "//" in url else f"//{url}")
    return (parts.hostname or "").lower()


def _scheme_of(url: str) -> str:
    from urllib.parse import urlsplit

    return (urlsplit(url).scheme or "").lower()


def _default_port(scheme) -> int:
    return 80 if str(scheme).lower() == "http" else 443
