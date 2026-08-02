"""Continuous monitoring and subscans (Phase 4 §Continuous monitoring and subscans).

reNgine-inspired behavior, written clean-room (no GPL code):

* a **schedule** holds an *immutable* discovery configuration and produces full
  scan requests from it (the config identity is a hash — it cannot drift);
* snapshot diffs (from :mod:`aegis.graph`) drive **narrow dependent subscans** for
  the assets that were added or changed;
* a subscan **retains the parent authorization/scope digest and cannot widen it** —
  a target outside the parent scope is refused;
* **repeated incomplete scans cannot declare asset removal** — removals come only
  from :func:`aegis.graph.confirmed_removals` (complete scans that agree);
* every stage/notification has a durable **activity record**.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from aegis.graph import confirmed_removals, diff_snapshots
from aegis.policy.scope import ScopeGuard


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ScopeWidened(RuntimeError):
    """A subscan tried to target something outside the parent scope."""


@dataclass(frozen=True)
class MonitorSchedule:
    schedule_id: str
    tenant_id: str
    engagement_id: str
    scope_digest: str
    targets: tuple[str, ...]           # the authorized scope (immutable)
    manifest_set: tuple[str, ...]      # discovery adapters (immutable)
    cadence_seconds: int
    config_hash: str                   # identity of the immutable config
    created_at: datetime


def new_schedule(*, tenant_id, engagement_id, scope_digest, targets, manifest_set,
                 cadence_seconds, schedule_id=None) -> MonitorSchedule:
    targets = tuple(sorted(set(targets)))
    manifest_set = tuple(sorted(set(manifest_set)))
    config_hash = hashlib.sha256(json.dumps(
        {"tenant": tenant_id, "engagement": engagement_id, "scope_digest": scope_digest,
         "targets": list(targets), "manifests": list(manifest_set), "cadence": cadence_seconds},
        sort_keys=True).encode("utf-8")).hexdigest()
    return MonitorSchedule(
        schedule_id=schedule_id or uuid.uuid4().hex, tenant_id=tenant_id,
        engagement_id=engagement_id, scope_digest=scope_digest, targets=targets,
        manifest_set=manifest_set, cadence_seconds=cadence_seconds, config_hash=config_hash,
        created_at=_now())


@dataclass(frozen=True)
class ScanRequest:
    tenant_id: str
    engagement_id: str
    scope_digest: str
    targets: tuple[str, ...]
    manifest_set: tuple[str, ...]
    kind: str = "full"                 # full | subscan
    parent_scan_id: str | None = None
    reason: str = ""


@dataclass
class ActivityRecord:
    activity_id: str
    kind: str                          # scheduled | subscan | notification | removal | stage
    schedule_id: str
    detail: dict
    at: datetime


class ActivityLog:
    """Durable-ish activity trail; a sink callback persists it in production."""

    def __init__(self, on_record: Callable[[ActivityRecord], None] | None = None) -> None:
        self._records: list[ActivityRecord] = []
        self._on_record = on_record

    def record(self, kind: str, schedule_id: str, **detail) -> ActivityRecord:
        rec = ActivityRecord(uuid.uuid4().hex, kind, schedule_id, dict(detail), _now())
        self._records.append(rec)
        if self._on_record is not None:
            self._on_record(rec)
        return rec

    def records(self, kind: str | None = None) -> list[ActivityRecord]:
        return [r for r in self._records if kind is None or r.kind == kind]


class MonitoringPlanner:
    def __init__(self, *, activity: ActivityLog | None = None) -> None:
        self.activity = activity or ActivityLog()

    def full_scan(self, schedule: MonitorSchedule) -> ScanRequest:
        """A full discovery scan built from the frozen schedule config."""
        self.activity.record("scheduled", schedule.schedule_id, config_hash=schedule.config_hash)
        return ScanRequest(
            tenant_id=schedule.tenant_id, engagement_id=schedule.engagement_id,
            scope_digest=schedule.scope_digest, targets=schedule.targets,
            manifest_set=schedule.manifest_set, kind="full")

    def subscans_from_diff(self, schedule: MonitorSchedule, previous, current, *,
                           parent_scan_id: str, assets: dict) -> list[ScanRequest]:
        """Narrow subscans for added/changed assets; never widening the scope."""
        diff = diff_snapshots(previous, current)
        scope = ScopeGuard(list(schedule.targets))
        requests: list[ScanRequest] = []
        seen: set[str] = set()
        for key in [*diff.added, *diff.changed]:
            asset = assets.get(key)
            target = _target_of(key, asset)
            if not target or target in seen:
                continue
            if not scope.is_allowed(target):
                # A subscan may never reach outside the parent's authorized scope.
                raise ScopeWidened(f"{target!r} (from {key!r}) is outside the parent scope")
            seen.add(target)
            reason = "added" if key in diff.added else "changed"
            requests.append(ScanRequest(
                tenant_id=schedule.tenant_id, engagement_id=schedule.engagement_id,
                scope_digest=schedule.scope_digest,          # parent digest, unchanged
                targets=(target,), manifest_set=schedule.manifest_set,
                kind="subscan", parent_scan_id=parent_scan_id, reason=reason))
            self.activity.record("subscan", schedule.schedule_id, target=target, reason=reason,
                                 parent_scan_id=parent_scan_id, scope_digest=schedule.scope_digest)
        return requests

    def confirmed_asset_removals(self, schedule: MonitorSchedule, snapshots,
                                 *, required_agreeing_scans: int = 2) -> list[str]:
        """Only complete scans that agree can declare a removal."""
        removed = confirmed_removals(snapshots, required_agreeing_scans=required_agreeing_scans)
        for key in removed:
            self.activity.record("removal", schedule.schedule_id, asset_key=key,
                                 agreeing_scans=required_agreeing_scans)
        return removed


def _target_of(asset_key: str, asset) -> str:
    if asset is not None:
        host = asset.attributes.get("host") or asset.attributes.get("identifier")
        if host and "://" not in str(host) and "/" not in str(host):
            return str(host).lower()
    # Derive from the natural key as a fallback.
    if asset_key.startswith("domain:"):
        return asset_key.split(":", 1)[1]
    if asset_key.startswith("route:"):
        rest = asset_key.split(" ", 1)[-1]
        return rest.split("/", 1)[0]
    if asset_key.startswith(("service:", "tech:")):
        return asset_key.split(":", 2)[1].split(":")[0]
    return ""
