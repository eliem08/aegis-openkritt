"""Durable scan execution model (Master Prompt §durable state; Phase 1).

The records the scheduler and adapters persist: ``ScanRun`` → ``StageRun`` →
``TaskRun``, with a ``TaskLease`` (compare-and-set ownership + heartbeat) and
``Artifact`` metadata. Tasks are idempotent by
``(scan, stage, target, adapter version, input hash)`` — one live lease per key.
Task state transitions are validated (invalid transitions fail closed), and
expired leases are reclaimed on restart without repeating non-retryable work.

Dataclasses + serde live here; the concrete SQLite/Postgres methods live on the
repositories (shared behavioral contract).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum


def dt_from_iso(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _now() -> datetime:
    return datetime.now(timezone.utc)


class TaskState(str, Enum):
    QUEUED = "queued"
    LEASED = "leased"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    RETRYABLE_FAILED = "retryable_failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"
    QUARANTINED = "quarantined"


TERMINAL_STATES = {
    TaskState.SUCCEEDED,
    TaskState.CANCELLED,
    TaskState.QUARANTINED,
    TaskState.BLOCKED,
}

# Allowed transitions; anything else fails closed.
VALID_TRANSITIONS: dict[TaskState, set[TaskState]] = {
    TaskState.QUEUED: {TaskState.LEASED, TaskState.CANCELLED, TaskState.BLOCKED},
    TaskState.LEASED: {
        TaskState.RUNNING, TaskState.QUEUED, TaskState.CANCELLED,
        TaskState.QUARANTINED, TaskState.RETRYABLE_FAILED,
    },
    TaskState.RUNNING: {
        TaskState.SUCCEEDED, TaskState.RETRYABLE_FAILED, TaskState.BLOCKED,
        TaskState.CANCELLED, TaskState.QUARANTINED,
    },
    TaskState.RETRYABLE_FAILED: {TaskState.QUEUED, TaskState.CANCELLED, TaskState.BLOCKED},
}
# States whose entry releases any held lease.
_LEASE_RELEASING = TERMINAL_STATES | {TaskState.QUEUED}


class InvalidTaskTransition(Exception):
    pass


def can_transition(current: TaskState, new: TaskState) -> bool:
    return new in VALID_TRANSITIONS.get(current, set())


def releases_lease(new: TaskState) -> bool:
    return new in _LEASE_RELEASING


def task_idempotency_key(
    scan_id: str, stage_id: str, target: str, adapter_version: str, input_hash: str
) -> str:
    raw = "|".join([scan_id, stage_id, target, adapter_version, input_hash])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# --- records ---------------------------------------------------------------

@dataclass
class ScanRun:
    scan_id: str
    tenant_id: str
    engagement_id: str
    scope_digest: str
    config_hash: str
    status: str
    manifest_set: list[str]
    created_at: datetime
    updated_at: datetime


@dataclass
class StageRun:
    stage_id: str
    scan_id: str
    stage_type: str
    depends_on: list[str]
    input_hash: str
    status: str
    retry_policy: dict
    created_at: datetime


@dataclass
class TaskRun:
    task_id: str
    scan_id: str
    stage_id: str
    target: str
    adapter: str
    adapter_version: str
    capability_tier: str
    quotas: dict
    idempotency_key: str
    status: str
    result_summary: dict | None
    attempts: int
    max_attempts: int
    retryable: bool
    created_at: datetime
    updated_at: datetime


@dataclass
class TaskLease:
    lease_id: str
    task_id: str
    owner: str
    heartbeat_at: datetime
    expires_at: datetime
    cancelled: bool
    created_at: datetime


@dataclass
class Artifact:
    artifact_id: str
    task_id: str
    kind: str
    classification: str
    checksum: str
    storage_ref: str | None
    size: int
    retention_deadline: datetime | None
    created_at: datetime


# --- column orders + serde -------------------------------------------------

SCAN_COLS = "scan_id, tenant_id, engagement_id, scope_digest, config_hash, status, manifest_set, created_at, updated_at"
STAGE_COLS = "stage_id, scan_id, stage_type, depends_on, input_hash, status, retry_policy, created_at"
TASK_COLS = ("task_id, scan_id, stage_id, target, adapter, adapter_version, capability_tier, quotas, "
             "idempotency_key, status, result_summary, attempts, max_attempts, retryable, created_at, updated_at")
LEASE_COLS = "lease_id, task_id, owner, heartbeat_at, expires_at, cancelled, created_at"
ARTIFACT_COLS = "artifact_id, task_id, kind, classification, checksum, storage_ref, size, retention_deadline, created_at"


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def scan_values(s: ScanRun) -> tuple:
    return (s.scan_id, s.tenant_id, s.engagement_id, s.scope_digest, s.config_hash, s.status,
            json.dumps(s.manifest_set), s.created_at.isoformat(), s.updated_at.isoformat())


def scan_from_row(r) -> ScanRun:
    return ScanRun(r[0], r[1], r[2], r[3], r[4], r[5], json.loads(r[6] or "[]"),
                   dt_from_iso(r[7]), dt_from_iso(r[8]))


def stage_values(s: StageRun) -> tuple:
    return (s.stage_id, s.scan_id, s.stage_type, json.dumps(s.depends_on), s.input_hash, s.status,
            json.dumps(s.retry_policy), s.created_at.isoformat())


def stage_from_row(r) -> StageRun:
    return StageRun(r[0], r[1], r[2], json.loads(r[3] or "[]"), r[4], r[5],
                    json.loads(r[6] or "{}"), dt_from_iso(r[7]))


def task_values(t: TaskRun) -> tuple:
    return (t.task_id, t.scan_id, t.stage_id, t.target, t.adapter, t.adapter_version, t.capability_tier,
            json.dumps(t.quotas), t.idempotency_key, t.status,
            json.dumps(t.result_summary) if t.result_summary is not None else None,
            t.attempts, t.max_attempts, int(t.retryable), t.created_at.isoformat(), t.updated_at.isoformat())


def task_from_row(r) -> TaskRun:
    return TaskRun(r[0], r[1], r[2], r[3], r[4], r[5], r[6], json.loads(r[7] or "{}"), r[8], r[9],
                   json.loads(r[10]) if r[10] else None, r[11], r[12], bool(r[13]),
                   dt_from_iso(r[14]), dt_from_iso(r[15]))


def lease_values(le: TaskLease) -> tuple:
    return (le.lease_id, le.task_id, le.owner, le.heartbeat_at.isoformat(), le.expires_at.isoformat(),
            int(le.cancelled), le.created_at.isoformat())


def lease_from_row(r) -> TaskLease:
    return TaskLease(r[0], r[1], r[2], dt_from_iso(r[3]), dt_from_iso(r[4]), bool(r[5]), dt_from_iso(r[6]))


def artifact_values(a: Artifact) -> tuple:
    return (a.artifact_id, a.task_id, a.kind, a.classification, a.checksum, a.storage_ref, a.size,
            _iso(a.retention_deadline), a.created_at.isoformat())


def artifact_from_row(r) -> Artifact:
    return Artifact(r[0], r[1], r[2], r[3], r[4], r[5], r[6], dt_from_iso(r[7]), dt_from_iso(r[8]))


# --- factories -------------------------------------------------------------

def new_scan(*, tenant_id, engagement_id, scope_digest="", config_hash="",
             manifest_set=None, scan_id=None) -> ScanRun:
    now = _now()
    return ScanRun(scan_id or uuid.uuid4().hex, tenant_id, engagement_id, scope_digest, config_hash,
                   "created", list(manifest_set or []), now, now)


def new_stage(*, scan_id, stage_type, depends_on=None, input_hash="", retry_policy=None,
              stage_id=None) -> StageRun:
    return StageRun(stage_id or uuid.uuid4().hex, scan_id, stage_type, list(depends_on or []),
                    input_hash, "queued", dict(retry_policy or {}), _now())


def new_task(*, scan_id, stage_id, target, adapter, adapter_version, capability_tier="passive_discovery",
             quotas=None, input_hash="", max_attempts=3, retryable=True, task_id=None) -> TaskRun:
    now = _now()
    key = task_idempotency_key(scan_id, stage_id, target, adapter_version, input_hash)
    return TaskRun(task_id or uuid.uuid4().hex, scan_id, stage_id, target, adapter, adapter_version,
                   capability_tier, dict(quotas or {}), key, TaskState.QUEUED.value, None, 0,
                   max_attempts, retryable, now, now)
