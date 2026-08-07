"""Asset/observation graph (Phase 2 §Normalization and asset graph).

Two layers, deliberately separated:

* **Observations are immutable facts.** Every adapter emission becomes its own
  observation row carrying who saw it (adapter + provider), when, and with what
  confidence. Nothing ever rewrites or deletes one.
* **Assets are the derived view.** Deduplication merges observations that share a
  *natural key* into one asset, unioning provenance. Merging updates the derived
  view; it never destroys the observations behind it.

Natural keys are canonical strings — readable, stable, and distinct per kind — so
the same domain/service/URL/route/parameter/technology seen by five different
tools collapses to one asset with five sources.

Each scan produces an :class:`AssetSnapshot`. Diffs label assets added, changed,
unchanged, or missing; **missing is never removal** until a configurable number of
*complete* scans agree (:func:`confirmed_removals`), so a partial or failed scan
cannot erase an asset.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from urllib.parse import parse_qsl, urlsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _now() -> datetime:
    return datetime.now(UTC)


class AssetKind(str, Enum):
    DOMAIN = "domain"
    SERVICE = "service"
    URL = "url"
    ROUTE = "route"
    PARAMETER = "parameter"
    TECHNOLOGY = "technology"


# --- natural keys ----------------------------------------------------------

def normalize_hostname(raw: str) -> str:
    """Bare, lowercased hostname from a host, ``host:port``, or URL."""
    if not raw or not raw.strip():
        raise ValueError("empty host")
    text = raw.strip()
    parts = urlsplit(text if "//" in text else f"//{text}")
    host = parts.hostname
    if not host:
        raise ValueError(f"could not extract host from {raw!r}")
    return host.lower().rstrip(".")


def canonical_url(raw: str) -> str:
    """Canonical URL for deduplication.

    Lowercases scheme/host, drops a default port and a trailing slash, and keeps
    query parameter **names while dropping their values** — two hits on the same
    endpoint with different values are one URL, but a method-relevant parameter
    name is never discarded (Phase 2 §gau adapter).
    """
    if not raw or not raw.strip():
        raise ValueError("empty url")
    text = raw.strip()
    parts = urlsplit(text if "//" in text else f"//{text}")
    scheme = (parts.scheme or "https").lower()
    host = parts.hostname
    if not host:
        raise ValueError(f"could not extract host from {raw!r}")
    host = host.lower().rstrip(".")
    port = parts.port
    netloc = host if port is None or port == _DEFAULT_PORTS.get(scheme) else f"{host}:{port}"
    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    names = sorted({name for name, _value in parse_qsl(parts.query, keep_blank_values=True)})
    query = "&".join(names)
    return f"{scheme}://{netloc}{path}" + (f"?{query}" if query else "")


def domain_key(host: str) -> str:
    return f"domain:{normalize_hostname(host)}"


def service_key(host: str, port: int | str, scheme: str = "") -> str:
    label = f"{normalize_hostname(host)}:{port}"
    return f"service:{label}/{scheme.lower()}" if scheme else f"service:{label}"


def url_key(url: str) -> str:
    return f"url:{canonical_url(url)}"


def route_key(host: str, method: str, path: str) -> str:
    path = path if path.startswith("/") else f"/{path}"
    return f"route:{(method or 'GET').upper()} {normalize_hostname(host)}{path}"


def parameter_key(route: str, name: str, location: str = "query") -> str:
    # Parameters hang off their route, so the same name on two routes stays distinct.
    return f"param:{route}#{name}@{location.lower()}"


def technology_key(host: str, name: str, version: str = "") -> str:
    base = f"tech:{normalize_hostname(host)}:{name.strip().lower()}"
    return f"{base}@{version}" if version else base


# --- records ---------------------------------------------------------------

@dataclass(frozen=True)
class Observation:
    """An immutable fact: one adapter emission about one asset."""

    observation_id: str
    engagement_id: str
    scan_id: str
    task_id: str
    asset_key: str
    kind: AssetKind
    source: str            # adapter name
    provider: str          # upstream data provider (wayback, crtsh, ...), if any
    observed_at: datetime
    data: dict
    confidence: float = 1.0
    raw_ref: str | None = None


@dataclass
class Asset:
    """The derived, deduplicated view of everything observed under one key."""

    engagement_id: str
    asset_key: str
    kind: AssetKind
    attributes: dict = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)      # "adapter" or "adapter/provider"
    first_seen: datetime = field(default_factory=_now)
    last_seen: datetime = field(default_factory=_now)
    observation_count: int = 0

    def merge_observation(self, obs: Observation) -> Asset:
        """Fold an observation in. Provenance only ever grows."""
        for key, value in obs.data.items():
            if value is not None and value != "":
                self.attributes[key] = value
        label = f"{obs.source}/{obs.provider}" if obs.provider else obs.source
        if label not in self.sources:
            self.sources.append(label)
            self.sources.sort()
        self.first_seen = min(self.first_seen, obs.observed_at)
        self.last_seen = max(self.last_seen, obs.observed_at)
        self.observation_count += 1
        return self

    @property
    def digest(self) -> str:
        """Content digest — snapshot diffs use it to detect a *changed* asset."""
        payload = json.dumps(
            {"attributes": self.attributes, "sources": sorted(self.sources)},
            sort_keys=True, default=str,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def new_observation(
    *, engagement_id: str, scan_id: str, task_id: str, asset_key: str, kind: AssetKind,
    source: str, data: dict, provider: str = "", observed_at: datetime | None = None,
    confidence: float = 1.0, raw_ref: str | None = None,
) -> Observation:
    return Observation(
        observation_id=uuid.uuid4().hex, engagement_id=engagement_id, scan_id=scan_id,
        task_id=task_id, asset_key=asset_key, kind=kind, source=source, provider=provider,
        observed_at=observed_at or _now(), data=dict(data), confidence=confidence, raw_ref=raw_ref,
    )


# --- snapshots + diffs -----------------------------------------------------

@dataclass(frozen=True)
class AssetSnapshot:
    """What one scan saw. ``complete`` is false when coverage was partial —
    an incomplete snapshot may never justify a removal."""

    snapshot_id: str
    engagement_id: str
    scan_id: str
    entries: dict[str, str]        # asset_key -> content digest
    complete: bool
    created_at: datetime

    @property
    def keys(self) -> set[str]:
        return set(self.entries)


def new_snapshot(*, engagement_id: str, scan_id: str, assets, complete: bool) -> AssetSnapshot:
    return AssetSnapshot(
        snapshot_id=uuid.uuid4().hex, engagement_id=engagement_id, scan_id=scan_id,
        entries={a.asset_key: a.digest for a in assets}, complete=complete, created_at=_now(),
    )


class DiffStatus(str, Enum):
    ADDED = "added"
    CHANGED = "changed"
    UNCHANGED = "unchanged"
    MISSING = "missing"


@dataclass(frozen=True)
class SnapshotDiff:
    added: list[str]
    changed: list[str]
    unchanged: list[str]
    missing: list[str]
    removal_safe: bool   # False when either side was an incomplete scan

    def status(self, asset_key: str) -> DiffStatus | None:
        for status, keys in (
            (DiffStatus.ADDED, self.added), (DiffStatus.CHANGED, self.changed),
            (DiffStatus.UNCHANGED, self.unchanged), (DiffStatus.MISSING, self.missing),
        ):
            if asset_key in keys:
                return status
        return None


def diff_snapshots(previous: AssetSnapshot | None, current: AssetSnapshot) -> SnapshotDiff:
    """Label every asset added/changed/unchanged/missing.

    ``missing`` means "not seen in this scan" — **not** "removed". Removal is a
    separate, deliberately conservative decision (:func:`confirmed_removals`), and
    ``removal_safe`` is false whenever either scan was incomplete.
    """
    if previous is None:
        return SnapshotDiff(sorted(current.keys), [], [], [], removal_safe=False)

    added, changed, unchanged = [], [], []
    for key, digest in current.entries.items():
        if key not in previous.entries:
            added.append(key)
        elif previous.entries[key] != digest:
            changed.append(key)
        else:
            unchanged.append(key)
    missing = [k for k in previous.entries if k not in current.entries]
    return SnapshotDiff(
        sorted(added), sorted(changed), sorted(unchanged), sorted(missing),
        removal_safe=previous.complete and current.complete,
    )


def confirmed_removals(snapshots: list[AssetSnapshot], *, required_agreeing_scans: int = 2) -> list[str]:
    """Assets safe to treat as removed.

    Only **complete** scans get a vote (a partial scan proves nothing about what is
    gone). An asset is removed only when the last ``required_agreeing_scans``
    complete scans all agree it is absent *and* an earlier complete scan saw it.
    """
    if required_agreeing_scans < 1:
        raise ValueError("required_agreeing_scans must be >= 1")
    complete = [s for s in snapshots if s.complete]
    if len(complete) <= required_agreeing_scans:
        return []  # not enough agreeing evidence to call anything removed

    recent = complete[-required_agreeing_scans:]
    earlier = complete[: -required_agreeing_scans]
    seen_before: set[str] = set().union(*(s.keys for s in earlier))
    absent_now = [k for k in seen_before if all(k not in s.entries for s in recent)]
    return sorted(absent_now)
