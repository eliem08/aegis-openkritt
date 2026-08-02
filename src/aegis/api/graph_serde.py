"""Row serde for the asset graph (Phase 2).

Keeps database concerns here and the domain model in :mod:`aegis.graph`. Both the
SQLite and Postgres repositories share these column orders and converters, so the
two engines round-trip identically.
"""

from __future__ import annotations

import json
from datetime import datetime

from aegis.graph import Asset, AssetKind, AssetSnapshot, Observation

OBSERVATION_COLS = (
    "observation_id, engagement_id, scan_id, task_id, asset_key, kind, source, provider, "
    "observed_at, data, confidence, raw_ref, state"
)

# Promotion lifecycle. The observation's *content* never changes; only whether a
# validated-but-unfinished task's output has been accepted into the asset view.
PROVISIONAL = "provisional"   # streamed while the producing task is still running
PROMOTED = "promoted"         # task completed cleanly; counts toward the graph
QUARANTINED = "quarantined"   # task was quarantined; never counts toward the graph
ASSET_COLS = (
    "engagement_id, asset_key, kind, attributes, sources, first_seen, last_seen, observation_count"
)
SNAPSHOT_COLS = "snapshot_id, engagement_id, scan_id, entries, complete, created_at"


def dt_from_iso(value) -> datetime | None:
    # Local copy (not imported from persistence) so this module stays importable
    # by the repositories without a circular import.
    if value is None or isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value)


def observation_values(o: Observation, state: str = PROMOTED) -> tuple:
    return (
        o.observation_id, o.engagement_id, o.scan_id, o.task_id, o.asset_key,
        o.kind.value if hasattr(o.kind, "value") else o.kind, o.source, o.provider,
        o.observed_at.isoformat(), json.dumps(o.data, default=str), o.confidence, o.raw_ref,
        state,
    )


def observation_from_row(r) -> Observation:
    return Observation(
        observation_id=r[0], engagement_id=r[1], scan_id=r[2], task_id=r[3], asset_key=r[4],
        kind=AssetKind(r[5]), source=r[6], provider=r[7] or "", observed_at=dt_from_iso(r[8]),
        data=json.loads(r[9] or "{}"), confidence=r[10], raw_ref=r[11],
    )


def asset_values(a: Asset) -> tuple:
    return (
        a.engagement_id, a.asset_key, a.kind.value if hasattr(a.kind, "value") else a.kind,
        json.dumps(a.attributes, default=str), json.dumps(sorted(a.sources)),
        a.first_seen.isoformat(), a.last_seen.isoformat(), a.observation_count,
    )


def asset_from_row(r) -> Asset:
    return Asset(
        engagement_id=r[0], asset_key=r[1], kind=AssetKind(r[2]),
        attributes=json.loads(r[3] or "{}"), sources=json.loads(r[4] or "[]"),
        first_seen=dt_from_iso(r[5]), last_seen=dt_from_iso(r[6]), observation_count=r[7] or 0,
    )


def merge_asset_row(row, incoming: Asset) -> Asset:
    """Merge an incoming asset into the stored one — provenance only ever grows."""
    if row is None:
        return incoming
    current = asset_from_row(row)
    current.attributes.update(incoming.attributes)
    for source in incoming.sources:
        if source not in current.sources:
            current.sources.append(source)
    current.sources.sort()
    current.first_seen = min(current.first_seen, incoming.first_seen)
    current.last_seen = max(current.last_seen, incoming.last_seen)
    current.observation_count += incoming.observation_count
    return current


def snapshot_values(s: AssetSnapshot) -> tuple:
    return (
        s.snapshot_id, s.engagement_id, s.scan_id, json.dumps(s.entries, sort_keys=True),
        int(s.complete), s.created_at.isoformat(),
    )


def snapshot_from_row(r) -> AssetSnapshot:
    return AssetSnapshot(
        snapshot_id=r[0], engagement_id=r[1], scan_id=r[2], entries=json.loads(r[3] or "{}"),
        complete=bool(r[4]), created_at=dt_from_iso(r[5]),
    )
