"""gau adapter — historical URL discovery (Phase 2 §gau adapter).

Reads URLs that third-party archives already recorded (Wayback, Common Crawl,
OTX, URLScan). This stage **sends no traffic to the target**: the network profile
is ``passive-provider``, so the gateway permits the configured provider hosts and
nothing else — a discovered target URL is data here, never a request.

Provider and the archive's original observation timestamp are preserved so the
asset graph can say not just "this URL exists" but "Wayback saw it in 2024".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .base import QUOTA_EXHAUSTED, JsonLinesAdapter, SchemaMismatch
from .contract import AdapterManifest, CapabilityTier, EventKind, ExecutionEnvelope

GAU_MANIFEST = AdapterManifest(
    name="gau",
    version="2.2.4",
    executable_digest="",          # pin the release digest before distribution
    license="MIT",
    capability_tier=CapabilityTier.PASSIVE_DISCOVERY.value,
    input_schema_version=1,
    output_schema_version=1,
    network_profile="passive-provider",
)

DEFAULT_PROVIDERS = ("wayback", "commoncrawl", "otx", "urlscan")
# Static assets rarely carry parameters worth testing; excluded by default.
DEFAULT_EXCLUDED_EXTENSIONS = (
    "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2", "ttf", "eot", "css",
)


@dataclass(frozen=True)
class GauConfig:
    providers: tuple[str, ...] = DEFAULT_PROVIDERS
    max_results: int = 5000
    from_date: str = ""            # YYYYMM
    to_date: str = ""              # YYYYMM
    exclude_extensions: tuple[str, ...] = DEFAULT_EXCLUDED_EXTENSIONS
    include_status: tuple[int, ...] = ()      # empty = any
    exclude_mime: tuple[str, ...] = field(default_factory=tuple)


class GauAdapter(JsonLinesAdapter):
    manifest = GAU_MANIFEST
    tool_name = "gau"

    def __init__(self, executable=None, *, config: GauConfig | None = None, **kw) -> None:
        super().__init__(executable, **kw)
        self.config = config or GauConfig()
        self._count = 0
        self._providers_seen: set[str] = set()
        self._filtered = 0

    def build_command(self, envelope: ExecutionEnvelope) -> list[str]:
        cfg = self.config
        argv = [
            self.resolve_executable(),
            "--json", "--subs",
            "--providers", ",".join(cfg.providers),
            "--threads", "5",
        ]
        if cfg.from_date:
            argv += ["--from", cfg.from_date]
        if cfg.to_date:
            argv += ["--to", cfg.to_date]
        if cfg.exclude_extensions:
            argv += ["--blacklist", ",".join(cfg.exclude_extensions)]
        argv.append(envelope.target)
        return argv

    def map_record(self, record: dict, envelope: ExecutionEnvelope):
        url = record.get("url")
        if not url:
            raise SchemaMismatch("gau record has no 'url' field")

        if self._count >= self.config.max_results:
            return (EventKind.DIAGNOSTIC,
                    {"code": QUOTA_EXHAUSTED, "message": "max results reached", "blocking": False}, 0.0)

        provider = str(record.get("provider") or record.get("source") or "unknown")
        if self._excluded(str(url), record):
            self._filtered += 1
            return None

        self._count += 1
        self._providers_seen.add(provider)
        data = {
            "identifier": str(url),
            "asset_type": "url",
            "provider": provider,
            "historical": True,
        }
        observed = _parse_timestamp(record.get("date") or record.get("timestamp"))
        if observed:
            # The archive's original sighting, not when we ran.
            data["original_observed_at"] = observed.isoformat()
        for key in ("status", "mime", "length"):
            if record.get(key) not in (None, ""):
                data[key] = record[key]
        return (EventKind.ASSET, data, 1.0)

    def _excluded(self, url: str, record: dict) -> bool:
        cfg = self.config
        path = url.split("?", 1)[0].split("#", 1)[0]
        ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
        if ext and ext in cfg.exclude_extensions:
            return True
        if cfg.include_status and record.get("status") not in (None, ""):
            try:
                if int(record["status"]) not in cfg.include_status:
                    return True
            except (TypeError, ValueError):
                return True
        mime = str(record.get("mime") or "").lower()
        if mime and any(mime.startswith(m) for m in cfg.exclude_mime):
            return True
        return False

    def interpret_result(self, result, envelope: ExecutionEnvelope):
        event = super().interpret_result(result, envelope)
        missing = [p for p in self.config.providers if p not in self._providers_seen]
        event.data.update({
            "results": self._count,
            "filtered": self._filtered,
            "providers_seen": sorted(self._providers_seen),
            "providers_without_results": missing,
            "coverage": "complete" if not missing else "partial",
        })
        return event


def _parse_timestamp(raw) -> datetime | None:
    """Archive timestamps arrive as ``YYYYMMDDhhmmss``, ``YYYYMMDD``, or ISO."""
    if raw in (None, ""):
        return None
    text = str(raw).strip()
    for fmt in ("%Y%m%d%H%M%S", "%Y%m%d", "%Y%m"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
