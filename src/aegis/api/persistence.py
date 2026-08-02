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
from datetime import datetime, timezone

from aegis.policy.killswitch import KillSwitchState

from .store import ApprovalGrant, EngagementRecord

# --- pure, DB-agnostic serialization (shared with Postgres, unit-testable) ---


def dt_from_iso(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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
"""


class SqliteRepository:
    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def save_engagement(self, record: EngagementRecord) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO engagements(id, auth_json, status, created_at) VALUES (?,?,?,?)",
                engagement_values(record),
            )
            self._conn.commit()

    def get_engagement(self, engagement_id: str) -> EngagementRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, auth_json, status, created_at FROM engagements WHERE id=?", (engagement_id,)
            ).fetchone()
        return engagement_from_row(row) if row else None

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
                (engagement_id, json.dumps(record), now_iso()),
            )
            self._conn.commit()

    def recent_audit(self, engagement_id: str, limit: int) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT record FROM audit WHERE engagement_id=? ORDER BY seq DESC LIMIT ?",
                (engagement_id, limit),
            ).fetchall()
        return [json.loads(r[0]) for r in reversed(rows)]

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

    def close(self) -> None:
        with self._lock:
            self._conn.close()
