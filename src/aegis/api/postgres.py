"""PostgreSQL implementation of the durable :class:`Repository` (§12) — HA path.

Same protocol and same row representation as :class:`SqliteRepository` (it reuses
the shared serialization helpers), so switching stores is a config change
(``AEGIS_DB_URL``). Requires ``psycopg`` (v3) and a reachable Postgres.

A single autocommit connection guarded by a lock serializes DB access — simple
and correct for the control plane's scale; swap in ``psycopg_pool`` for higher
concurrency. Values are stored as TEXT/INTEGER for parity with SQLite.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from psycopg_pool import ConnectionPool

from aegis.policy.killswitch import KillSwitchState

from . import scans
from .migrations import Migration, run_migrations
from .persistence import (
    _RES_COLS,
    _SESSION_USAGE_SQL,
    _SPEND_USAGE_SQL,
    engagement_from_row,
    engagement_values,
    grant_from_row,
    grant_values,
    kill_from_row,
    kill_values,
    now_iso,
    reservation_from_row,
    reservation_values,
)
from .store import ApprovalGrant, EngagementRecord, PolicyReservation

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
    seq BIGSERIAL PRIMARY KEY, engagement_id TEXT NOT NULL, record TEXT NOT NULL, ts TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_eng ON audit(engagement_id);
CREATE TABLE IF NOT EXISTS kill_state (
    engagement_id TEXT PRIMARY KEY, fired INTEGER, reason TEXT, source TEXT, fired_at TEXT
);
CREATE TABLE IF NOT EXISTS spend (engagement_id TEXT PRIMARY KEY, spent DOUBLE PRECISION);
CREATE TABLE IF NOT EXISTS reservations (
    reservation_id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, spend DOUBLE PRECISION, sessions INTEGER,
    spend_final DOUBLE PRECISION, status TEXT NOT NULL, idempotency_key TEXT UNIQUE, expires_at TEXT, created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_res_eng ON reservations(engagement_id);
"""

_SCAN_SCHEMA_PG = """
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

POSTGRES_MIGRATIONS = [
    Migration(1, "initial_schema", _SCHEMA),
    Migration(2, "scan_model", _SCAN_SCHEMA_PG),
]
_MIGRATION_LOCK_ID = 8234110001  # arbitrary constant; serialises migration across instances


class PostgresRepository:
    def __init__(self, dsn: str, *, encryptor=None, min_size: int = 1, max_size: int = 8) -> None:
        from .crypto import NullEncryptor

        self._dsn = dsn
        self._enc = encryptor or NullEncryptor()
        self._pool = ConnectionPool(
            dsn, min_size=min_size, max_size=max_size, kwargs={"autocommit": True}, open=True
        )
        self._migrate()

    def _migrate(self) -> None:
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(%s)", (_MIGRATION_LOCK_ID,))
            try:
                def query(sql, params=()):
                    cur.execute(sql, params)
                    return cur.fetchall()

                run_migrations(
                    POSTGRES_MIGRATIONS,
                    execute_script=lambda sql: cur.execute(sql),
                    execute=lambda sql, params=(): cur.execute(sql, params),
                    query=query,
                    placeholder="%s",
                )
            finally:
                cur.execute("SELECT pg_advisory_unlock(%s)", (_MIGRATION_LOCK_ID,))

    def _exec(self, sql: str, params: tuple = ()):
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(sql, params)

    def _query(self, sql: str, params: tuple = ()) -> list[tuple]:
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()

    def save_engagement(self, record: EngagementRecord) -> None:
        eid, auth_json, status, created = engagement_values(record)
        self._exec(
            "INSERT INTO engagements(id, auth_json, status, created_at) VALUES (%s,%s,%s,%s) "
            "ON CONFLICT (id) DO UPDATE SET auth_json=EXCLUDED.auth_json, status=EXCLUDED.status, "
            "created_at=EXCLUDED.created_at",
            (eid, self._enc.encrypt(auth_json), status, created),
        )

    def get_engagement(self, engagement_id: str) -> EngagementRecord | None:
        rows = self._query(
            "SELECT id, auth_json, status, created_at FROM engagements WHERE id=%s", (engagement_id,)
        )
        if not rows:
            return None
        r = rows[0]
        return engagement_from_row((r[0], self._enc.decrypt(r[1]), r[2], r[3]))

    def list_engagement_ids(self) -> list[str]:
        return [r[0] for r in self._query("SELECT id FROM engagements")]

    def update_engagement_status(self, engagement_id: str, status: str) -> None:
        self._exec("UPDATE engagements SET status=%s WHERE id=%s", (status, engagement_id))

    def save_grant(self, engagement_id: str, grant: ApprovalGrant) -> None:
        self._exec(
            "INSERT INTO grants(grant_id, engagement_id, action, target, tokens, granted_by, "
            "granted_at, expires_at, single_use, used, revoked) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
            "ON CONFLICT (grant_id) DO UPDATE SET action=EXCLUDED.action, target=EXCLUDED.target, "
            "tokens=EXCLUDED.tokens, granted_by=EXCLUDED.granted_by, granted_at=EXCLUDED.granted_at, "
            "expires_at=EXCLUDED.expires_at, single_use=EXCLUDED.single_use, used=EXCLUDED.used, "
            "revoked=EXCLUDED.revoked",
            grant_values(engagement_id, grant),
        )

    def list_grants(self, engagement_id: str) -> list[ApprovalGrant]:
        rows = self._query(
            "SELECT grant_id, action, target, tokens, granted_by, granted_at, expires_at, "
            "single_use, used, revoked FROM grants WHERE engagement_id=%s", (engagement_id,)
        )
        return [grant_from_row(r) for r in rows]

    def append_audit(self, engagement_id: str, record: dict) -> None:
        self._exec(
            "INSERT INTO audit(engagement_id, record, ts) VALUES (%s,%s,%s)",
            (engagement_id, self._enc.encrypt(json.dumps(record)), now_iso()),
        )

    def recent_audit(self, engagement_id: str, limit: int) -> list[dict]:
        rows = self._query(
            "SELECT record FROM audit WHERE engagement_id=%s ORDER BY seq DESC LIMIT %s",
            (engagement_id, limit),
        )
        return [json.loads(self._enc.decrypt(r[0])) for r in reversed(rows)]

    def save_kill_state(self, engagement_id: str, state: KillSwitchState) -> None:
        self._exec(
            "INSERT INTO kill_state(engagement_id, fired, reason, source, fired_at) VALUES (%s,%s,%s,%s,%s) "
            "ON CONFLICT (engagement_id) DO UPDATE SET fired=EXCLUDED.fired, reason=EXCLUDED.reason, "
            "source=EXCLUDED.source, fired_at=EXCLUDED.fired_at",
            kill_values(engagement_id, state),
        )

    def get_kill_state(self, engagement_id: str) -> KillSwitchState | None:
        rows = self._query(
            "SELECT fired, reason, source, fired_at FROM kill_state WHERE engagement_id=%s", (engagement_id,)
        )
        return kill_from_row(rows[0]) if rows else None

    def save_spend(self, engagement_id: str, spent: float) -> None:
        self._exec(
            "INSERT INTO spend(engagement_id, spent) VALUES (%s,%s) "
            "ON CONFLICT (engagement_id) DO UPDATE SET spent=EXCLUDED.spent",
            (engagement_id, spent),
        )

    def get_spend(self, engagement_id: str) -> float | None:
        rows = self._query("SELECT spent FROM spend WHERE engagement_id=%s", (engagement_id,))
        return rows[0][0] if rows else None

    # -- atomic reservations (per-engagement advisory lock serializes reserves) --

    def reserve(self, engagement_id, *, spend, sessions, spend_cap, session_cap,
                idempotency_key, expires_at=None) -> PolicyReservation | None:
        with self._pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (engagement_id,))
            cur.execute(f"SELECT {_RES_COLS} FROM reservations WHERE idempotency_key=%s", (idempotency_key,))
            existing = cur.fetchone()
            if existing is not None:
                return reservation_from_row(existing)

            cur.execute(_SPEND_USAGE_SQL.format(ph="%s"), (engagement_id,))
            spend_used = cur.fetchone()[0] or 0.0
            cur.execute(_SESSION_USAGE_SQL.format(ph="%s"), (engagement_id,))
            sessions_used = cur.fetchone()[0] or 0

            if spend_cap is not None and spend_used + spend > spend_cap:
                return None
            if session_cap is not None and sessions_used + sessions > session_cap:
                return None

            res = PolicyReservation(
                reservation_id=uuid.uuid4().hex, engagement_id=engagement_id, spend=spend,
                sessions=sessions, spend_final=None, status="reserved",
                idempotency_key=idempotency_key, expires_at=expires_at,
                created_at=datetime.now(timezone.utc),
            )
            cur.execute(
                f"INSERT INTO reservations({_RES_COLS}) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                reservation_values(res),
            )
            return res

    def finalize(self, reservation_id, actual_spend) -> PolicyReservation | None:
        with self._pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
            cur.execute(
                f"SELECT {_RES_COLS} FROM reservations WHERE reservation_id=%s FOR UPDATE", (reservation_id,)
            )
            row = cur.fetchone()
            if row is None:
                return None
            res = reservation_from_row(row)
            if res.status != "reserved":
                return res
            cur.execute(
                "UPDATE reservations SET status='finalized', spend_final=%s WHERE reservation_id=%s",
                (actual_spend, reservation_id),
            )
            res.status, res.spend_final = "finalized", actual_spend
            return res

    def release(self, reservation_id) -> PolicyReservation | None:
        with self._pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
            cur.execute(
                f"SELECT {_RES_COLS} FROM reservations WHERE reservation_id=%s FOR UPDATE", (reservation_id,)
            )
            row = cur.fetchone()
            if row is None:
                return None
            res = reservation_from_row(row)
            if res.status == "reserved":
                cur.execute(
                    "UPDATE reservations SET status='released' WHERE reservation_id=%s", (reservation_id,)
                )
                res.status = "released"
            return res

    def reservation_usage(self, engagement_id) -> tuple[float, int]:
        spend = self._query(_SPEND_USAGE_SQL.format(ph="%s"), (engagement_id,))[0][0] or 0.0
        sessions = self._query(_SESSION_USAGE_SQL.format(ph="%s"), (engagement_id,))[0][0] or 0
        return (float(spend), int(sessions))

    # -- durable scan model --

    def create_scan(self, scan) -> None:
        self._exec(f"INSERT INTO scan_runs({scans.SCAN_COLS}) VALUES ({','.join(['%s'] * 9)})", scans.scan_values(scan))

    def get_scan(self, scan_id):
        rows = self._query(f"SELECT {scans.SCAN_COLS} FROM scan_runs WHERE scan_id=%s", (scan_id,))
        return scans.scan_from_row(rows[0]) if rows else None

    def scans_for_tenant(self, tenant_id=None):
        if tenant_id is None:
            rows = self._query(f"SELECT {scans.SCAN_COLS} FROM scan_runs ORDER BY created_at DESC")
        else:
            rows = self._query(
                f"SELECT {scans.SCAN_COLS} FROM scan_runs WHERE tenant_id=%s ORDER BY created_at DESC",
                (tenant_id,))
        return [scans.scan_from_row(r) for r in rows]

    def create_stage(self, stage) -> None:
        self._exec(f"INSERT INTO stage_runs({scans.STAGE_COLS}) VALUES ({','.join(['%s'] * 8)})", scans.stage_values(stage))

    def stages_for_scan(self, scan_id):
        return [scans.stage_from_row(r) for r in self._query(f"SELECT {scans.STAGE_COLS} FROM stage_runs WHERE scan_id=%s", (scan_id,))]

    def create_task(self, task):
        with self._pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
            cur.execute(f"SELECT {scans.TASK_COLS} FROM task_runs WHERE idempotency_key=%s", (task.idempotency_key,))
            existing = cur.fetchone()
            if existing is not None:
                return scans.task_from_row(existing)
            cur.execute(f"INSERT INTO task_runs({scans.TASK_COLS}) VALUES ({','.join(['%s'] * 16)})", scans.task_values(task))
            return task

    def get_task(self, task_id):
        rows = self._query(f"SELECT {scans.TASK_COLS} FROM task_runs WHERE task_id=%s", (task_id,))
        return scans.task_from_row(rows[0]) if rows else None

    def tasks_for_scan(self, scan_id):
        return [scans.task_from_row(r) for r in self._query(f"SELECT {scans.TASK_COLS} FROM task_runs WHERE scan_id=%s", (scan_id,))]

    def lease_task(self, task_id, owner, ttl_seconds=300):
        import uuid as _uuid

        now = datetime.now(timezone.utc)
        with self._pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
            cur.execute(f"SELECT {scans.TASK_COLS} FROM task_runs WHERE task_id=%s FOR UPDATE", (task_id,))
            trow = cur.fetchone()
            if trow is None or scans.task_from_row(trow).status != scans.TaskState.QUEUED.value:
                return None
            cur.execute(f"SELECT {scans.LEASE_COLS} FROM task_leases WHERE task_id=%s FOR UPDATE", (task_id,))
            lrow = cur.fetchone()
            if lrow is not None:
                lease = scans.lease_from_row(lrow)
                if not lease.cancelled and lease.expires_at > now:
                    return None
                cur.execute("DELETE FROM task_leases WHERE task_id=%s", (task_id,))
            lease = scans.TaskLease(
                lease_id=_uuid.uuid4().hex, task_id=task_id, owner=owner, heartbeat_at=now,
                expires_at=now + timedelta(seconds=ttl_seconds), cancelled=False, created_at=now,
            )
            cur.execute(f"INSERT INTO task_leases({scans.LEASE_COLS}) VALUES ({','.join(['%s'] * 7)})", scans.lease_values(lease))
            cur.execute("UPDATE task_runs SET status=%s, updated_at=%s WHERE task_id=%s",
                        (scans.TaskState.LEASED.value, now.isoformat(), task_id))
            return lease

    def heartbeat(self, lease_id, ttl_seconds=300) -> bool:
        now = datetime.now(timezone.utc)
        with self._pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
            cur.execute(f"SELECT {scans.LEASE_COLS} FROM task_leases WHERE lease_id=%s FOR UPDATE", (lease_id,))
            lrow = cur.fetchone()
            if lrow is None or bool(lrow[5]):
                return False
            cur.execute("UPDATE task_leases SET heartbeat_at=%s, expires_at=%s WHERE lease_id=%s",
                        (now.isoformat(), (now + timedelta(seconds=ttl_seconds)).isoformat(), lease_id))
            return True

    def heartbeat_task(self, task_id, owner=None, ttl_seconds=300) -> bool:
        rows = self._query("SELECT lease_id, owner, cancelled FROM task_leases WHERE task_id=%s", (task_id,))
        if not rows or bool(rows[0][2]) or (owner is not None and rows[0][1] != owner):
            return False
        return self.heartbeat(rows[0][0], ttl_seconds)

    def transition_task(self, task_id, new_state, result_summary=None):
        now = datetime.now(timezone.utc)
        target = scans.TaskState(new_state) if isinstance(new_state, str) else new_state
        with self._pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
            cur.execute(f"SELECT {scans.TASK_COLS} FROM task_runs WHERE task_id=%s FOR UPDATE", (task_id,))
            trow = cur.fetchone()
            if trow is None:
                return None
            task = scans.task_from_row(trow)
            if not scans.can_transition(scans.TaskState(task.status), target):
                raise scans.InvalidTaskTransition(f"{task.status} -> {target.value}")
            cur.execute(
                "UPDATE task_runs SET status=%s, result_summary=COALESCE(%s, result_summary), updated_at=%s WHERE task_id=%s",
                (target.value, json.dumps(result_summary) if result_summary is not None else None, now.isoformat(), task_id),
            )
            if scans.releases_lease(target):
                cur.execute("DELETE FROM task_leases WHERE task_id=%s", (task_id,))
            task.status, task.updated_at = target.value, now
            if result_summary is not None:
                task.result_summary = result_summary
            return task

    def reclaim_expired_leases(self, now=None):
        now = now or datetime.now(timezone.utc)
        now_iso_s = now.isoformat()
        reclaimed = []
        with self._pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
            cur.execute(
                "SELECT tl.task_id, tr.attempts, tr.max_attempts, tr.retryable FROM task_leases tl "
                "JOIN task_runs tr ON tl.task_id=tr.task_id "
                "WHERE tl.cancelled=0 AND tl.expires_at <= %s AND tr.status IN ('leased','running') FOR UPDATE",
                (now_iso_s,),
            )
            for task_id, attempts, max_attempts, retryable in cur.fetchall():
                if retryable and attempts < max_attempts:
                    cur.execute("UPDATE task_runs SET status='queued', attempts=attempts+1, updated_at=%s WHERE task_id=%s",
                                (now_iso_s, task_id))
                    new_status = "queued"
                else:
                    cur.execute("UPDATE task_runs SET status='blocked', updated_at=%s WHERE task_id=%s", (now_iso_s, task_id))
                    new_status = "blocked"
                cur.execute("DELETE FROM task_leases WHERE task_id=%s", (task_id,))
                reclaimed.append((task_id, new_status))
        return reclaimed

    def create_artifact(self, artifact) -> None:
        self._exec(f"INSERT INTO artifacts({scans.ARTIFACT_COLS}) VALUES ({','.join(['%s'] * 9)})", scans.artifact_values(artifact))

    def artifacts_for_task(self, task_id):
        return [scans.artifact_from_row(r) for r in self._query(f"SELECT {scans.ARTIFACT_COLS} FROM artifacts WHERE task_id=%s", (task_id,))]

    def get_artifact(self, artifact_id):
        rows = self._query(f"SELECT {scans.ARTIFACT_COLS} FROM artifacts WHERE artifact_id=%s", (artifact_id,))
        return scans.artifact_from_row(rows[0]) if rows else None

    def close(self) -> None:
        self._pool.close()
