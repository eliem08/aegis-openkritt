"""SQLite implementation of the durable :class:`Repository` (§12).

Stdlib-only (``sqlite3``), so durability needs no external service and is fully
testable. WAL mode + a write lock make it safe under FastAPI's threadpool.

The row<->object serialization is factored into pure helpers shared with the
Postgres implementation (:mod:`aegis.api.postgres`), so both stores speak the
same on-disk representation and the conversion logic is unit-tested without a DB.
Everything is stored as TEXT/INTEGER for portability across engines.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from aegis.policy.killswitch import KillSwitchState

from . import graph_serde, scans
from .migrations import Migration, run_migrations
from .store import ApprovalGrant, EngagementRecord, PolicyReservation

# --- pure, DB-agnostic serialization (shared with Postgres, unit-testable) ---


def dt_from_iso(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def engagement_values(record: EngagementRecord) -> tuple:
    return (record.id, json.dumps(record.authorization), record.status, record.created_at.isoformat())


def engagement_from_row(row) -> EngagementRecord:  # (id, auth_json, status, created_at)
    return EngagementRecord(
        id=row[0], authorization=json.loads(row[1]), status=row[2], created_at=dt_from_iso(row[3])
    )


def grant_values(engagement_id: str, g: ApprovalGrant) -> tuple:
    return (
        g.grant_id, engagement_id, g.action, g.target, json.dumps(sorted(g.tokens)), g.granted_by,
        g.granted_at.isoformat(), g.expires_at.isoformat() if g.expires_at else None,
        int(g.single_use), int(g.used), int(g.revoked),
    )


def grant_from_row(row) -> ApprovalGrant:
    # (grant_id, action, target, tokens, granted_by, granted_at, expires_at, single_use, used, revoked)
    return ApprovalGrant(
        grant_id=row[0], action=row[1], target=row[2], tokens=frozenset(json.loads(row[3])),
        granted_by=row[4], granted_at=dt_from_iso(row[5]), expires_at=dt_from_iso(row[6]),
        single_use=bool(row[7]), used=bool(row[8]), revoked=bool(row[9]),
    )


def kill_values(engagement_id: str, state: KillSwitchState) -> tuple:
    return (
        engagement_id, int(state.fired), state.reason, state.source,
        state.fired_at.isoformat() if state.fired_at else None,
    )


def kill_from_row(row) -> KillSwitchState | None:  # (fired, reason, source, fired_at)
    if row is None or not row[0]:
        return None  # only rehydrate a *fired* switch
    return KillSwitchState(fired=True, reason=row[1], source=row[2], fired_at=dt_from_iso(row[3]))


def reservation_values(r: PolicyReservation) -> tuple:
    return (
        r.reservation_id, r.engagement_id, r.spend, r.sessions, r.spend_final, r.status,
        r.idempotency_key, r.expires_at.isoformat() if r.expires_at else None, r.created_at.isoformat(),
    )


def reservation_from_row(row) -> PolicyReservation:
    # (reservation_id, engagement_id, spend, sessions, spend_final, status, idempotency_key, expires_at, created_at)
    return PolicyReservation(
        reservation_id=row[0], engagement_id=row[1], spend=row[2], sessions=row[3],
        spend_final=row[4], status=row[5], idempotency_key=row[6],
        expires_at=dt_from_iso(row[7]), created_at=dt_from_iso(row[8]),
    )


# SQL fragments shared by both engines (usage over non-released reservations).
_SPEND_USAGE_SQL = (
    "SELECT COALESCE(SUM(CASE WHEN status='finalized' THEN spend_final ELSE spend END), 0) "
    "FROM reservations WHERE engagement_id={ph} AND status IN ('reserved','finalized')"
)
_SESSION_USAGE_SQL = (
    "SELECT COALESCE(SUM(sessions), 0) FROM reservations WHERE engagement_id={ph} AND status='reserved'"
)
_RES_COLS = "reservation_id, engagement_id, spend, sessions, spend_final, status, idempotency_key, expires_at, created_at"


@dataclass(frozen=True)
class TaskProgress:
    """Partial progress, deliberately separate from a task's completion status."""

    task_id: str
    scan_id: str
    stage_id: str
    events: int
    assets: int
    rejected: int
    updated_at: datetime | None


def _progress_from_row(row) -> TaskProgress | None:
    if row is None:
        return None
    return TaskProgress(row[0], row[1], row[2] or "", row[3] or 0, row[4] or 0, row[5] or 0,
                        dt_from_iso(row[6]))


def _state_clause(states, placeholder: str = "?") -> tuple[str, tuple]:
    """Optional ``state IN (...)`` filter; ``None`` means every state."""
    if not states:
        return "", ()
    marks = ",".join([placeholder] * len(states))
    return f" AND state IN ({marks})", tuple(states)


# --- SQLite repository ----------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY, auth_json TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS grants (
    grant_id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, action TEXT, target TEXT,
    tokens TEXT, granted_by TEXT, granted_at TEXT, expires_at TEXT,
    single_use INTEGER, used INTEGER, revoked INTEGER
);
CREATE INDEX IF NOT EXISTS idx_grants_eng ON grants(engagement_id);
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, engagement_id TEXT NOT NULL, record TEXT NOT NULL, ts TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_eng ON audit(engagement_id);
CREATE TABLE IF NOT EXISTS kill_state (
    engagement_id TEXT PRIMARY KEY, fired INTEGER, reason TEXT, source TEXT, fired_at TEXT
);
CREATE TABLE IF NOT EXISTS spend (engagement_id TEXT PRIMARY KEY, spent REAL);
CREATE TABLE IF NOT EXISTS reservations (
    reservation_id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, spend REAL, sessions INTEGER,
    spend_final REAL, status TEXT NOT NULL, idempotency_key TEXT UNIQUE, expires_at TEXT, created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_res_eng ON reservations(engagement_id);
"""

_SCAN_SCHEMA_SQLITE = """
CREATE TABLE IF NOT EXISTS scan_runs (
    scan_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    scope_digest TEXT, config_hash TEXT, status TEXT NOT NULL, manifest_set TEXT,
    created_at TEXT, updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_eng ON scan_runs(engagement_id);
CREATE TABLE IF NOT EXISTS stage_runs (
    stage_id TEXT PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scan_runs(scan_id),
    stage_type TEXT, depends_on TEXT, input_hash TEXT, status TEXT NOT NULL, retry_policy TEXT, created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_stage_scan ON stage_runs(scan_id);
CREATE TABLE IF NOT EXISTS task_runs (
    task_id TEXT PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scan_runs(scan_id), stage_id TEXT NOT NULL,
    target TEXT, adapter TEXT, adapter_version TEXT, capability_tier TEXT, quotas TEXT,
    idempotency_key TEXT UNIQUE, status TEXT NOT NULL, result_summary TEXT,
    attempts INTEGER, max_attempts INTEGER, retryable INTEGER, created_at TEXT, updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_task_scan ON task_runs(scan_id);
CREATE TABLE IF NOT EXISTS task_leases (
    lease_id TEXT PRIMARY KEY, task_id TEXT NOT NULL UNIQUE REFERENCES task_runs(task_id),
    owner TEXT, heartbeat_at TEXT, expires_at TEXT, cancelled INTEGER, created_at TEXT
);
CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES task_runs(task_id),
    kind TEXT, classification TEXT, checksum TEXT, storage_ref TEXT, size INTEGER,
    retention_deadline TEXT, created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_artifact_task ON artifacts(task_id);
"""

_GRAPH_SCHEMA_SQLITE = """
CREATE TABLE IF NOT EXISTS observations (
    observation_id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scan_runs(scan_id), task_id TEXT,
    asset_key TEXT NOT NULL, kind TEXT NOT NULL, source TEXT, provider TEXT,
    observed_at TEXT, data TEXT, confidence REAL, raw_ref TEXT
);
CREATE INDEX IF NOT EXISTS idx_obs_scan ON observations(scan_id);
CREATE INDEX IF NOT EXISTS idx_obs_asset ON observations(engagement_id, asset_key);
CREATE TABLE IF NOT EXISTS assets (
    engagement_id TEXT NOT NULL, asset_key TEXT NOT NULL, kind TEXT NOT NULL,
    attributes TEXT, sources TEXT, first_seen TEXT, last_seen TEXT,
    observation_count INTEGER, PRIMARY KEY (engagement_id, asset_key)
);
CREATE TABLE IF NOT EXISTS asset_snapshots (
    snapshot_id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scan_runs(scan_id),
    entries TEXT, complete INTEGER, created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_snap_eng ON asset_snapshots(engagement_id);
"""

_STREAMING_SCHEMA_SQLITE = """
ALTER TABLE observations ADD COLUMN state TEXT NOT NULL DEFAULT 'promoted';
CREATE INDEX IF NOT EXISTS idx_obs_state ON observations(task_id, state);
ALTER TABLE stage_runs ADD COLUMN stream_from TEXT NOT NULL DEFAULT '[]';
ALTER TABLE stage_runs ADD COLUMN min_stream_events INTEGER NOT NULL DEFAULT 1;
CREATE TABLE IF NOT EXISTS task_progress (
    task_id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, stage_id TEXT,
    events INTEGER, assets INTEGER, rejected INTEGER, updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_progress_scan ON task_progress(scan_id);
"""

# The full baseline schema is migration 0001; later schema changes append here.
SQLITE_MIGRATIONS = [
    Migration(1, "initial_schema", _SCHEMA),
    Migration(2, "scan_model", _SCAN_SCHEMA_SQLITE),
    Migration(3, "asset_graph", _GRAPH_SCHEMA_SQLITE),
    Migration(4, "streaming_progress", _STREAMING_SCHEMA_SQLITE),
]


class SqliteRepository:
    def __init__(self, path: str, *, encryptor=None) -> None:
        from .crypto import NullEncryptor

        self._path = path
        self._enc = encryptor or NullEncryptor()
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        with self._lock:
            run_migrations(
                SQLITE_MIGRATIONS,
                execute_script=self._conn.executescript,
                execute=lambda sql, params=(): self._conn.execute(sql, params),
                query=lambda sql, params=(): self._conn.execute(sql, params).fetchall(),
                placeholder="?",
            )
            self._conn.commit()

    def save_engagement(self, record: EngagementRecord) -> None:
        eid, auth_json, status, created = engagement_values(record)
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO engagements(id, auth_json, status, created_at) VALUES (?,?,?,?)",
                (eid, self._enc.encrypt(auth_json), status, created),
            )
            self._conn.commit()

    def get_engagement(self, engagement_id: str) -> EngagementRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, auth_json, status, created_at FROM engagements WHERE id=?", (engagement_id,)
            ).fetchone()
        if not row:
            return None
        return engagement_from_row((row[0], self._enc.decrypt(row[1]), row[2], row[3]))

    def list_engagement_ids(self) -> list[str]:
        with self._lock:
            return [r[0] for r in self._conn.execute("SELECT id FROM engagements").fetchall()]

    def update_engagement_status(self, engagement_id: str, status: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE engagements SET status=? WHERE id=?", (status, engagement_id))
            self._conn.commit()

    def save_grant(self, engagement_id: str, grant: ApprovalGrant) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO grants(grant_id, engagement_id, action, target, tokens, "
                "granted_by, granted_at, expires_at, single_use, used, revoked) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                grant_values(engagement_id, grant),
            )
            self._conn.commit()

    def list_grants(self, engagement_id: str) -> list[ApprovalGrant]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT grant_id, action, target, tokens, granted_by, granted_at, expires_at, "
                "single_use, used, revoked FROM grants WHERE engagement_id=?", (engagement_id,)
            ).fetchall()
        return [grant_from_row(r) for r in rows]

    def append_audit(self, engagement_id: str, record: dict) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit(engagement_id, record, ts) VALUES (?,?,?)",
                (engagement_id, self._enc.encrypt(json.dumps(record)), now_iso()),
            )
            self._conn.commit()

    def recent_audit(self, engagement_id: str, limit: int) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT record FROM audit WHERE engagement_id=? ORDER BY seq DESC LIMIT ?",
                (engagement_id, limit),
            ).fetchall()
        return [json.loads(self._enc.decrypt(r[0])) for r in reversed(rows)]

    def save_kill_state(self, engagement_id: str, state: KillSwitchState) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO kill_state(engagement_id, fired, reason, source, fired_at) "
                "VALUES (?,?,?,?,?)",
                kill_values(engagement_id, state),
            )
            self._conn.commit()

    def get_kill_state(self, engagement_id: str) -> KillSwitchState | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT fired, reason, source, fired_at FROM kill_state WHERE engagement_id=?",
                (engagement_id,),
            ).fetchone()
        return kill_from_row(row)

    def save_spend(self, engagement_id: str, spent: float) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO spend(engagement_id, spent) VALUES (?,?)", (engagement_id, spent)
            )
            self._conn.commit()

    def get_spend(self, engagement_id: str) -> float | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT spent FROM spend WHERE engagement_id=?", (engagement_id,)
            ).fetchone()
        return row[0] if row else None

    # -- atomic reservations (BEGIN IMMEDIATE serializes concurrent reserves) --

    def _consume_single_use(self, engagement_id, consume_approval) -> bool:
        """Within an open transaction, burn the active single-use grant(s) matching
        ``(action, target)``. Returns False (fail closed) if none is consumable."""
        action, target = consume_approval
        now = datetime.now(UTC)
        rows = self._conn.execute(
            "SELECT grant_id, expires_at FROM grants WHERE engagement_id=? AND action=? "
            "AND target=? AND single_use=1 AND used=0 AND revoked=0",
            (engagement_id, action, target),
        ).fetchall()
        active = [gid for gid, exp in rows if exp is None or dt_from_iso(exp) >= now]
        if not active:
            return False
        self._conn.execute(
            f"UPDATE grants SET used=1 WHERE grant_id IN ({','.join('?' * len(active))})", active
        )
        return True

    def reserve(self, engagement_id, *, spend, sessions, spend_cap, session_cap,
                idempotency_key, expires_at=None, consume_approval=None) -> PolicyReservation | None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    f"SELECT {_RES_COLS} FROM reservations WHERE idempotency_key=?", (idempotency_key,)
                ).fetchone()
                if existing is not None:
                    self._conn.commit()
                    return reservation_from_row(existing)  # idempotent: never re-consume

                spend_used = self._conn.execute(
                    _SPEND_USAGE_SQL.format(ph="?"), (engagement_id,)
                ).fetchone()[0] or 0.0
                sessions_used = self._conn.execute(
                    _SESSION_USAGE_SQL.format(ph="?"), (engagement_id,)
                ).fetchone()[0] or 0

                if spend_cap is not None and spend_used + spend > spend_cap:
                    self._conn.rollback()  # over cap: nothing claimed, no approval burned
                    return None
                if session_cap is not None and sessions_used + sessions > session_cap:
                    self._conn.rollback()
                    return None

                # Burn a single-use approval in the SAME transaction as the claim, so
                # two concurrent reservations can never both consume one token.
                if consume_approval is not None and not self._consume_single_use(engagement_id, consume_approval):
                    self._conn.rollback()  # fail closed: no consumable single-use approval
                    return None

                res = PolicyReservation(
                    reservation_id=uuid.uuid4().hex, engagement_id=engagement_id, spend=spend,
                    sessions=sessions, spend_final=None, status="reserved",
                    idempotency_key=idempotency_key, expires_at=expires_at,
                    created_at=datetime.now(UTC),
                )
                self._conn.execute(
                    f"INSERT INTO reservations({_RES_COLS}) VALUES (?,?,?,?,?,?,?,?,?)",
                    reservation_values(res),
                )
                self._conn.commit()
                return res
            except Exception:
                self._conn.rollback()
                raise

    def finalize(self, reservation_id, actual_spend) -> PolicyReservation | None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    f"SELECT {_RES_COLS} FROM reservations WHERE reservation_id=?", (reservation_id,)
                ).fetchone()
                if row is None:
                    self._conn.commit()
                    return None
                res = reservation_from_row(row)
                if res.status != "reserved":  # idempotent
                    self._conn.commit()
                    return res
                self._conn.execute(
                    "UPDATE reservations SET status='finalized', spend_final=? WHERE reservation_id=?",
                    (actual_spend, reservation_id),
                )
                self._conn.commit()
                res.status, res.spend_final = "finalized", actual_spend
                return res
            except Exception:
                self._conn.rollback()
                raise

    def release(self, reservation_id) -> PolicyReservation | None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    f"SELECT {_RES_COLS} FROM reservations WHERE reservation_id=?", (reservation_id,)
                ).fetchone()
                if row is None:
                    self._conn.commit()
                    return None
                res = reservation_from_row(row)
                if res.status == "reserved":
                    self._conn.execute(
                        "UPDATE reservations SET status='released' WHERE reservation_id=?", (reservation_id,)
                    )
                    res.status = "released"
                self._conn.commit()
                return res
            except Exception:
                self._conn.rollback()
                raise

    def reservation_usage(self, engagement_id) -> tuple[float, int]:
        with self._lock:
            spend = self._conn.execute(
                _SPEND_USAGE_SQL.format(ph="?"), (engagement_id,)
            ).fetchone()[0] or 0.0
            sessions = self._conn.execute(
                _SESSION_USAGE_SQL.format(ph="?"), (engagement_id,)
            ).fetchone()[0] or 0
        return (float(spend), int(sessions))

    # -- durable scan model --

    def create_scan(self, scan) -> None:
        ph = ",".join("?" * 9)
        with self._lock:
            self._conn.execute(f"INSERT INTO scan_runs({scans.SCAN_COLS}) VALUES ({ph})", scans.scan_values(scan))
            self._conn.commit()

    def get_scan(self, scan_id):
        with self._lock:
            row = self._conn.execute(f"SELECT {scans.SCAN_COLS} FROM scan_runs WHERE scan_id=?", (scan_id,)).fetchone()
        return scans.scan_from_row(row) if row else None

    def scans_for_tenant(self, tenant_id=None):
        """All scans, or only one tenant's (newest first)."""
        with self._lock:
            if tenant_id is None:
                rows = self._conn.execute(
                    f"SELECT {scans.SCAN_COLS} FROM scan_runs ORDER BY created_at DESC").fetchall()
            else:
                rows = self._conn.execute(
                    f"SELECT {scans.SCAN_COLS} FROM scan_runs WHERE tenant_id=? ORDER BY created_at DESC",
                    (tenant_id,)).fetchall()
        return [scans.scan_from_row(r) for r in rows]

    def create_stage(self, stage) -> None:
        ph = ",".join("?" * 10)
        with self._lock:
            self._conn.execute(f"INSERT INTO stage_runs({scans.STAGE_COLS}) VALUES ({ph})", scans.stage_values(stage))
            self._conn.commit()

    def stages_for_scan(self, scan_id):
        with self._lock:
            rows = self._conn.execute(f"SELECT {scans.STAGE_COLS} FROM stage_runs WHERE scan_id=?", (scan_id,)).fetchall()
        return [scans.stage_from_row(r) for r in rows]

    def create_task(self, task):
        """Idempotent: an existing task with the same idempotency key is returned."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    f"SELECT {scans.TASK_COLS} FROM task_runs WHERE idempotency_key=?", (task.idempotency_key,)
                ).fetchone()
                if existing is not None:
                    self._conn.commit()
                    return scans.task_from_row(existing)
                self._conn.execute(
                    f"INSERT INTO task_runs({scans.TASK_COLS}) VALUES ({','.join('?' * 16)})",
                    scans.task_values(task),
                )
                self._conn.commit()
                return task
            except Exception:
                self._conn.rollback()
                raise

    def get_task(self, task_id):
        with self._lock:
            row = self._conn.execute(f"SELECT {scans.TASK_COLS} FROM task_runs WHERE task_id=?", (task_id,)).fetchone()
        return scans.task_from_row(row) if row else None

    def tasks_for_scan(self, scan_id):
        with self._lock:
            rows = self._conn.execute(f"SELECT {scans.TASK_COLS} FROM task_runs WHERE scan_id=?", (scan_id,)).fetchall()
        return [scans.task_from_row(r) for r in rows]

    def lease_task(self, task_id, owner, ttl_seconds=300):
        now = datetime.now(UTC)
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                trow = self._conn.execute(f"SELECT {scans.TASK_COLS} FROM task_runs WHERE task_id=?", (task_id,)).fetchone()
                if trow is None or scans.task_from_row(trow).status != scans.TaskState.QUEUED.value:
                    self._conn.commit()
                    return None
                lrow = self._conn.execute(f"SELECT {scans.LEASE_COLS} FROM task_leases WHERE task_id=?", (task_id,)).fetchone()
                if lrow is not None:
                    lease = scans.lease_from_row(lrow)
                    if not lease.cancelled and lease.expires_at > now:
                        self._conn.commit()
                        return None  # a live lease already owns it (compare-and-set fails)
                    self._conn.execute("DELETE FROM task_leases WHERE task_id=?", (task_id,))
                lease = scans.TaskLease(
                    lease_id=uuid.uuid4().hex, task_id=task_id, owner=owner, heartbeat_at=now,
                    expires_at=now + timedelta(seconds=ttl_seconds), cancelled=False, created_at=now,
                )
                self._conn.execute(
                    f"INSERT INTO task_leases({scans.LEASE_COLS}) VALUES ({','.join('?' * 7)})", scans.lease_values(lease)
                )
                self._conn.execute(
                    "UPDATE task_runs SET status=?, updated_at=? WHERE task_id=?",
                    (scans.TaskState.LEASED.value, now.isoformat(), task_id),
                )
                self._conn.commit()
                return lease
            except Exception:
                self._conn.rollback()
                raise

    def heartbeat(self, lease_id, ttl_seconds=300) -> bool:
        now = datetime.now(UTC)
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                lrow = self._conn.execute(f"SELECT {scans.LEASE_COLS} FROM task_leases WHERE lease_id=?", (lease_id,)).fetchone()
                if lrow is None or bool(lrow[5]):
                    self._conn.commit()
                    return False
                self._conn.execute(
                    "UPDATE task_leases SET heartbeat_at=?, expires_at=? WHERE lease_id=?",
                    (now.isoformat(), (now + timedelta(seconds=ttl_seconds)).isoformat(), lease_id),
                )
                self._conn.commit()
                return True
            except Exception:
                self._conn.rollback()
                raise

    def heartbeat_task(self, task_id, owner=None, ttl_seconds=300) -> bool:
        """Extend the active lease on a task (optionally checking the owner)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT lease_id, owner, cancelled FROM task_leases WHERE task_id=?", (task_id,)).fetchone()
        if row is None or bool(row[2]) or (owner is not None and row[1] != owner):
            return False
        return self.heartbeat(row[0], ttl_seconds)

    def transition_task(self, task_id, new_state, result_summary=None):
        now = datetime.now(UTC)
        target = scans.TaskState(new_state) if isinstance(new_state, str) else new_state
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                trow = self._conn.execute(f"SELECT {scans.TASK_COLS} FROM task_runs WHERE task_id=?", (task_id,)).fetchone()
                if trow is None:
                    self._conn.commit()
                    return None
                task = scans.task_from_row(trow)
                if not scans.can_transition(scans.TaskState(task.status), target):
                    self._conn.rollback()
                    raise scans.InvalidTaskTransition(f"{task.status} -> {target.value}")
                self._conn.execute(
                    "UPDATE task_runs SET status=?, result_summary=COALESCE(?, result_summary), updated_at=? WHERE task_id=?",
                    (target.value, json.dumps(result_summary) if result_summary is not None else None, now.isoformat(), task_id),
                )
                if scans.releases_lease(target):
                    self._conn.execute("DELETE FROM task_leases WHERE task_id=?", (task_id,))
                self._conn.commit()
                task.status = target.value
                task.updated_at = now
                if result_summary is not None:
                    task.result_summary = result_summary
                return task
            except scans.InvalidTaskTransition:
                raise
            except Exception:
                self._conn.rollback()
                raise

    def reclaim_expired_leases(self, now=None):
        now = now or datetime.now(UTC)
        now_iso_s = now.isoformat()
        reclaimed = []
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                rows = self._conn.execute(
                    "SELECT tl.task_id, tr.attempts, tr.max_attempts, tr.retryable FROM task_leases tl "
                    "JOIN task_runs tr ON tl.task_id=tr.task_id "
                    "WHERE tl.cancelled=0 AND tl.expires_at <= ? AND tr.status IN ('leased','running')",
                    (now_iso_s,),
                ).fetchall()
                for task_id, attempts, max_attempts, retryable in rows:
                    if retryable and attempts < max_attempts:
                        self._conn.execute(
                            "UPDATE task_runs SET status='queued', attempts=attempts+1, updated_at=? WHERE task_id=?",
                            (now_iso_s, task_id),
                        )
                        new_status = "queued"
                    else:
                        self._conn.execute(
                            "UPDATE task_runs SET status='blocked', updated_at=? WHERE task_id=?", (now_iso_s, task_id)
                        )
                        new_status = "blocked"
                    self._conn.execute("DELETE FROM task_leases WHERE task_id=?", (task_id,))
                    reclaimed.append((task_id, new_status))
                self._conn.commit()
                return reclaimed
            except Exception:
                self._conn.rollback()
                raise

    def create_artifact(self, artifact) -> None:
        ph = ",".join("?" * 9)
        with self._lock:
            self._conn.execute(f"INSERT INTO artifacts({scans.ARTIFACT_COLS}) VALUES ({ph})", scans.artifact_values(artifact))
            self._conn.commit()

    def artifacts_for_task(self, task_id):
        with self._lock:
            rows = self._conn.execute(f"SELECT {scans.ARTIFACT_COLS} FROM artifacts WHERE task_id=?", (task_id,)).fetchall()
        return [scans.artifact_from_row(r) for r in rows]

    def get_artifact(self, artifact_id):
        with self._lock:
            row = self._conn.execute(
                f"SELECT {scans.ARTIFACT_COLS} FROM artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
        return scans.artifact_from_row(row) if row else None

    # -- asset graph (observations are append-only; assets are the derived view) --

    def record_observations(self, observations, state=graph_serde.PROMOTED) -> int:
        rows = [graph_serde.observation_values(o, state) for o in observations]
        if not rows:
            return 0
        with self._lock:
            self._conn.executemany(
                f"INSERT INTO observations({graph_serde.OBSERVATION_COLS}) VALUES ({','.join('?' * 13)})", rows
            )
            self._conn.commit()
        return len(rows)

    def observation_state_counts(self, task_id) -> dict:
        """``{state: count}`` for a task — the promotion lifecycle lives in the
        store, not on the immutable observation itself."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT state, COUNT(*) FROM observations WHERE task_id=? GROUP BY state", (task_id,)
            ).fetchall()
        return {r[0]: r[1] for r in rows}

    def set_observation_state(self, task_id, state, *, only_from=graph_serde.PROVISIONAL) -> int:
        """Promote or quarantine a task's streamed observations."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE observations SET state=? WHERE task_id=? AND state=?", (state, task_id, only_from)
            )
            self._conn.commit()
            return cur.rowcount

    def record_progress(self, task_id, scan_id, *, stage_id="", events=0, assets=0, rejected=0) -> None:
        """Partial progress, recorded separately from task completion."""
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO task_progress(task_id, scan_id, stage_id, events, assets, "
                "rejected, updated_at) VALUES (?,?,?,?,?,?,?)",
                (task_id, scan_id, stage_id, events, assets, rejected, now_iso()),
            )
            self._conn.commit()

    def get_progress(self, task_id):
        with self._lock:
            row = self._conn.execute(
                "SELECT task_id, scan_id, stage_id, events, assets, rejected, updated_at "
                "FROM task_progress WHERE task_id=?", (task_id,)).fetchone()
        return _progress_from_row(row)

    def progress_for_scan(self, scan_id):
        with self._lock:
            rows = self._conn.execute(
                "SELECT task_id, scan_id, stage_id, events, assets, rejected, updated_at "
                "FROM task_progress WHERE scan_id=?", (scan_id,)).fetchall()
        return [_progress_from_row(r) for r in rows]

    def upsert_assets(self, assets) -> int:
        """Merge assets into the derived view. Provenance unions; nothing is deleted."""
        assets = list(assets)
        if not assets:
            return 0
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                for asset in assets:
                    row = self._conn.execute(
                        f"SELECT {graph_serde.ASSET_COLS} FROM assets WHERE engagement_id=? AND asset_key=?",
                        (asset.engagement_id, asset.asset_key),
                    ).fetchone()
                    merged = graph_serde.merge_asset_row(row, asset)
                    self._conn.execute(
                        f"INSERT OR REPLACE INTO assets({graph_serde.ASSET_COLS}) VALUES ({','.join('?' * 8)})",
                        graph_serde.asset_values(merged),
                    )
                self._conn.commit()
                return len(assets)
            except Exception:
                self._conn.rollback()
                raise

    def assets_for_engagement(self, engagement_id, kind=None):
        sql = f"SELECT {graph_serde.ASSET_COLS} FROM assets WHERE engagement_id=?"
        params: tuple = (engagement_id,)
        if kind is not None:
            sql += " AND kind=?"
            params += (getattr(kind, "value", kind),)
        with self._lock:
            rows = self._conn.execute(sql + " ORDER BY asset_key", params).fetchall()
        return [graph_serde.asset_from_row(r) for r in rows]

    def observations_for_asset(self, engagement_id, asset_key, states=(graph_serde.PROMOTED,)):
        clause, params = _state_clause(states)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {graph_serde.OBSERVATION_COLS} FROM observations "
                f"WHERE engagement_id=? AND asset_key=?{clause} ORDER BY observed_at",
                (engagement_id, asset_key, *params),
            ).fetchall()
        return [graph_serde.observation_from_row(r) for r in rows]

    def observations_for_scan(self, scan_id, states=(graph_serde.PROMOTED,)):
        clause, params = _state_clause(states)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {graph_serde.OBSERVATION_COLS} FROM observations "
                f"WHERE scan_id=?{clause} ORDER BY observed_at",
                (scan_id, *params),
            ).fetchall()
        return [graph_serde.observation_from_row(r) for r in rows]

    def observations_for_task(self, task_id, states=None):
        """A task's own stream — includes provisional rows, for downstream stages."""
        clause, params = _state_clause(states)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {graph_serde.OBSERVATION_COLS} FROM observations "
                f"WHERE task_id=?{clause} ORDER BY observed_at",
                (task_id, *params),
            ).fetchall()
        return [graph_serde.observation_from_row(r) for r in rows]

    def save_snapshot(self, snapshot) -> None:
        with self._lock:
            self._conn.execute(
                f"INSERT OR REPLACE INTO asset_snapshots({graph_serde.SNAPSHOT_COLS}) VALUES ({','.join('?' * 6)})",
                graph_serde.snapshot_values(snapshot),
            )
            self._conn.commit()

    def snapshots_for_engagement(self, engagement_id):
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {graph_serde.SNAPSHOT_COLS} FROM asset_snapshots "
                "WHERE engagement_id=? ORDER BY created_at", (engagement_id,),
            ).fetchall()
        return [graph_serde.snapshot_from_row(r) for r in rows]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
