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

from psycopg_pool import ConnectionPool

from aegis.policy.killswitch import KillSwitchState

from .persistence import (
    engagement_from_row,
    engagement_values,
    grant_from_row,
    grant_values,
    kill_from_row,
    kill_values,
    now_iso,
)
from .store import ApprovalGrant, EngagementRecord

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
"""


class PostgresRepository:
    def __init__(self, dsn: str, *, encryptor=None, min_size: int = 1, max_size: int = 8) -> None:
        from .crypto import NullEncryptor

        self._dsn = dsn
        self._enc = encryptor or NullEncryptor()
        self._pool = ConnectionPool(
            dsn, min_size=min_size, max_size=max_size, kwargs={"autocommit": True}, open=True
        )
        self._exec(_SCHEMA)

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

    def close(self) -> None:
        self._pool.close()
