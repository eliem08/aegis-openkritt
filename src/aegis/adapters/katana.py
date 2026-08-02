"""Katana adapter — bounded crawling (Phase 2 §Katana adapter).

Standard (non-browser) crawling is the default and the only mode Phase 2 allows:
headless crawling needs the browser capability and stays disabled until Phase 4,
so asking for it here is a hard error rather than a silent downgrade.

Queue discipline is enforced in the adapter, not delegated to the tool: scope is
checked before a URL is ever enqueued (and again at the network gateway), depth
and page budgets are bounded, canonical URLs and near-identical pages are
deduplicated, configured logout paths are avoided, and hosts that keep failing
are backed off. Every route records where it was discovered and from which parent.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from .base import QUOTA_EXHAUSTED, TARGET_UNREACHABLE, JsonLinesAdapter, SchemaMismatch, in_parent_scope
from .contract import AdapterManifest, CapabilityTier, EventKind, ExecutionEnvelope
from .session import SessionBoundary

KATANA_MANIFEST = AdapterManifest(
    name="katana",
    version="1.1.0",
    executable_digest="",          # pin the release digest before distribution
    license="MIT",
    capability_tier=CapabilityTier.PASSIVE_DISCOVERY.value,
    input_schema_version=1,
    output_schema_version=2,
    network_profile="target-observation",
)

DEFAULT_LOGOUT_PATHS = ("/logout", "/signout", "/sign-out", "/log-out", "/session/destroy")


class HeadlessNotPermitted(RuntimeError):
    """Headless crawling requires the browser capability (Phase 4)."""


@dataclass(frozen=True)
class KatanaConfig:
    max_depth: int = 2
    max_pages: int = 500
    max_pages_per_host: int = 200
    max_forms: int = 50
    max_body_bytes: int = 1024 * 1024
    duration_seconds: int = 120
    concurrency: int = 5
    headless: bool = False
    logout_paths: tuple[str, ...] = DEFAULT_LOGOUT_PATHS
    unhealthy_host_threshold: int = 5   # consecutive failures before backing off


class KatanaAdapter(JsonLinesAdapter):
    manifest = KATANA_MANIFEST
    tool_name = "katana"

    def __init__(self, executable=None, *, config: KatanaConfig | None = None, **kw) -> None:
        super().__init__(executable, **kw)
        self.config = config or KatanaConfig()
        if self.config.headless:
            raise HeadlessNotPermitted(
                "headless crawling requires the browser capability and is disabled until Phase 4"
            )
        self._seen_urls: set[str] = set()
        self._seen_pages: set[str] = set()      # body hashes, for near-identical pages
        self._per_host: dict[str, int] = {}
        self._failures: dict[str, int] = {}
        self._backed_off: set[str] = set()
        self._forms = 0
        self._session: SessionBoundary | None = None

    def open_session(self, envelope: ExecutionEnvelope) -> SessionBoundary:
        """Session state for this task only; closed when the task ends."""
        self._session = SessionBoundary(
            task_id=envelope.task_id,
            scope_root=envelope.target,
            # The runner materializes credential *references* to a task-private
            # file; only its path is ever named, never a cookie value.
            cookie_file="session-cookies.txt" if envelope.credential_refs else "",
        )
        return self._session

    def close_session(self) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None

    def build_command(self, envelope: ExecutionEnvelope) -> list[str]:
        cfg = self.config
        argv = [
            self.resolve_executable(),
            "-u", envelope.target,
            "-jsonl", "-silent", "-no-color",
            "-depth", str(cfg.max_depth),
            "-crawl-duration", str(cfg.duration_seconds),
            "-concurrency", str(cfg.concurrency),
            "-strategy", "breadth-first",
            "-field-scope", "rdn",        # stay within the root domain
            "-crawl-scope", envelope.target,
            "-body-read-size", str(cfg.max_body_bytes),
            "-headless=false",            # explicit: never the browser engine in Phase 2
            "-disable-redirects",
        ]
        if envelope.credential_refs:
            session = self._session or self.open_session(envelope)
            # A path, never a value: argv is visible in process listings.
            argv += ["-automatic-form-fill=false", "-cookie-file", session.cookie_file]
        return argv

    def map_record(self, record: dict, envelope: ExecutionEnvelope):
        request = record.get("request")
        if not isinstance(request, dict):
            raise SchemaMismatch("katana record has no 'request' object")
        endpoint = request.get("endpoint") or request.get("url")
        if not endpoint:
            raise SchemaMismatch("katana request has no 'endpoint'")

        endpoint = str(endpoint)
        response = record.get("response") if isinstance(record.get("response"), dict) else {}
        parts = urlsplit(endpoint if "//" in endpoint else f"//{endpoint}")
        host = (parts.hostname or "").lower()
        method = str(request.get("method") or "GET").upper()

        # Cookies the crawl picked up stay inside the task's session boundary —
        # kept for in-scope hosts, dropped for anything else, never emitted.
        self._absorb_cookies(host, response)

        # Scope is enforced before enqueue; the gateway enforces it again on the wire.
        if not in_parent_scope(host, envelope.target):
            return (EventKind.DIAGNOSTIC,
                    {"code": "out_of_scope_url", "message": f"{endpoint} is outside {envelope.target}",
                     "blocking": False}, 0.0)

        if host in self._backed_off:
            return None  # unhealthy host: stop reporting until it recovers

        # A failing host is backed off rather than hammered.
        if response.get("status_code") in (429, 503) or record.get("error"):
            count = self._failures.get(host, 0) + 1
            self._failures[host] = count
            if count >= self.config.unhealthy_host_threshold:
                self._backed_off.add(host)
                return (EventKind.DIAGNOSTIC,
                        {"code": TARGET_UNREACHABLE, "message": f"backing off unhealthy host {host}",
                         "host": host, "blocking": False}, 0.0)
            return None
        self._failures.pop(host, None)

        path = parts.path or "/"
        if any(path.lower().rstrip("/") == p.rstrip("/") for p in self.config.logout_paths):
            return (EventKind.DIAGNOSTIC,
                    {"code": "logout_avoided", "message": f"skipped logout path {path}",
                     "blocking": False}, 0.0)

        if len(self._seen_urls) >= self.config.max_pages:
            return (EventKind.DIAGNOSTIC,
                    {"code": QUOTA_EXHAUSTED, "message": "max pages reached", "blocking": False}, 0.0)
        if self._per_host.get(host, 0) >= self.config.max_pages_per_host:
            return (EventKind.DIAGNOSTIC,
                    {"code": QUOTA_EXHAUSTED, "message": f"max pages for host {host}",
                     "blocking": False}, 0.0)

        # Canonical dedup: same method+path+parameter names is one route.
        param_names = sorted({name for name, _ in parse_qsl(parts.query, keep_blank_values=True)})
        canonical = f"{method} {host}{path}?{'&'.join(param_names)}"
        if canonical in self._seen_urls:
            return None
        # Near-identical pages (same body hash) add nothing new.
        body_hash = response.get("body_hash") or response.get("hash")
        if body_hash:
            if body_hash in self._seen_pages:
                return None
            self._seen_pages.add(body_hash)

        is_form = bool(request.get("body")) or str(request.get("tag") or "").lower() == "form"
        if is_form:
            if self._forms >= self.config.max_forms:
                return (EventKind.DIAGNOSTIC,
                        {"code": QUOTA_EXHAUSTED, "message": "max forms reached", "blocking": False}, 0.0)
            self._forms += 1

        self._seen_urls.add(canonical)
        self._per_host[host] = self._per_host.get(host, 0) + 1

        data = {
            "method": method,
            "path": path,
            "host": host,
            "url": endpoint,
            # Provenance: what pointed us here, and from where.
            "discovery_source": request.get("tag") or request.get("attribute") or "crawl",
            "parent_url": request.get("source") or "",
            "parameters": [{"name": n, "location": "query"} for n in param_names],
        }
        if response.get("status_code") is not None:
            data["status"] = response["status_code"]
        if body_hash:
            data["body_hash"] = body_hash
        if is_form:
            data["form"] = True
        # Last line of defence: no session material leaves the adapter, even if
        # the tool echoed a cookie or auth header back at us.
        return (EventKind.ROUTE, SessionBoundary.redact(data), 1.0)

    def _absorb_cookies(self, host: str, response: dict) -> None:
        if self._session is None or self._session.closed:
            return
        headers = response.get("headers") if isinstance(response.get("headers"), dict) else {}
        for key, value in list(headers.items()) + [("set-cookie", response.get("set_cookie"))]:
            if value and str(key).strip().lower() in ("set-cookie", "set_cookie"):
                self._session.store(host, str(value))

    def interpret_result(self, result, envelope: ExecutionEnvelope):
        event = super().interpret_result(result, envelope)
        event.data.update({
            "routes": len(self._seen_urls),
            "forms": self._forms,
            "hosts_backed_off": sorted(self._backed_off),
            "coverage": "partial" if self._backed_off else "complete",
        })
        return event
