"""SQLite implementation of the durable :class:`Repository` (§12).

Stdlib-only (``sqlite3``), so durability needs no external service and is fully
testable. WAL mode + a write lock make it safe under FastAPI's threadpool. A
Postgres repository would implement the same protocol and swap in via config.

Datetimes are stored as ISO-8601 strings; JSON columns hold the authorization
object, grant tokens, and audit records. Kill-switch state is only returned when
fired, so a fired switch survives a restart (fail-safe) while a never-fired one
rehydrates to the default.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone

from aegis.policy.killswitch import KillSwitchState

from .store import ApprovalGrant, EngagementRecord

_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY, authorization TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL
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


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SqliteRepository:
    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # -- engagements --

    def save_engagement(self, record: EngagementRecord) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO engagements(id, authorization, status, created_at) VALUES (?,?,?,?)",
                (record.id, json.dumps(record.authorization), record.status, record.created_at.isoformat()),
            )
            self._conn.commit()

    def get_engagement(self, engagement_id: str) -> EngagementRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, authorization, status, created_at FROM engagements WHERE id=?",
                (engagement_id,),
            ).fetchone()
        if row is None:
            return None
        return EngagementRecord(
            id=row[0], authorization=json.loads(row[1]), status=row[2], created_at=_dt(row[3])
        )

    def list_engagement_ids(self) -> list[str]:
        with self._lock:
            return [r[0] for r in self._conn.execute("SELECT id FROM engagements").fetchall()]

    def update_engagement_status(self, engagement_id: str, status: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE engagements SET status=? WHERE id=?", (status, engagement_id)
            )
            self._conn.commit()

    # -- grants --

    def save_grant(self, engagement_id: str, grant: ApprovalGrant) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO grants(grant_id, engagement_id, action, target, tokens, "
                "granted_by, granted_at, expires_at, single_use, used, revoked) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    grant.grant_id, engagement_id, grant.action, grant.target,
                    json.dumps(sorted(grant.tokens)), grant.granted_by, grant.granted_at.isoformat(),
                    grant.expires_at.isoformat() if grant.expires_at else None,
                    int(grant.single_use), int(grant.used), int(grant.revoked),
                ),
            )
            self._conn.commit()

    def list_grants(self, engagement_id: str) -> list[ApprovalGrant]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT grant_id, action, target, tokens, granted_by, granted_at, expires_at, "
                "single_use, used, revoked FROM grants WHERE engagement_id=?",
                (engagement_id,),
            ).fetchall()
        return [
            ApprovalGrant(
                grant_id=r[0], action=r[1], target=r[2], tokens=frozenset(json.loads(r[3])),
                granted_by=r[4], granted_at=_dt(r[5]), expires_at=_dt(r[6]),
                single_use=bool(r[7]), used=bool(r[8]), revoked=bool(r[9]),
            )
            for r in rows
        ]

    # -- audit --

    def append_audit(self, engagement_id: str, record: dict) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit(engagement_id, record, ts) VALUES (?,?,?)",
                (engagement_id, json.dumps(record), _now_iso()),
            )
            self._conn.commit()

    def recent_audit(self, engagement_id: str, limit: int) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT record FROM audit WHERE engagement_id=? ORDER BY seq DESC LIMIT ?",
                (engagement_id, limit),
            ).fetchall()
        return [json.loads(r[0]) for r in reversed(rows)]  # chronological order

    # -- kill switch --

    def save_kill_state(self, engagement_id: str, state: KillSwitchState) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO kill_state(engagement_id, fired, reason, source, fired_at) "
                "VALUES (?,?,?,?,?)",
                (
                    engagement_id, int(state.fired), state.reason, state.source,
                    state.fired_at.isoformat() if state.fired_at else None,
                ),
            )
            self._conn.commit()

    def get_kill_state(self, engagement_id: str) -> KillSwitchState | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT fired, reason, source, fired_at FROM kill_state WHERE engagement_id=?",
                (engagement_id,),
            ).fetchone()
        if row is None or not row[0]:
            return None  # only rehydrate a *fired* switch
        return KillSwitchState(fired=True, reason=row[1], source=row[2], fired_at=_dt(row[3]))

    # -- spend --

    def save_spend(self, engagement_id: str, spent: float) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO spend(engagement_id, spent) VALUES (?,?)",
                (engagement_id, spent),
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
