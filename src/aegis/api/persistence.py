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
from datetime import datetime, timezone

from aegis.policy.killswitch import KillSwitchState

from .migrations import Migration, run_migrations
from .store import ApprovalGrant, EngagementRecord, PolicyReservation

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

# The full baseline schema is migration 0001; later schema changes append here.
SQLITE_MIGRATIONS = [Migration(1, "initial_schema", _SCHEMA)]


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

    def reserve(self, engagement_id, *, spend, sessions, spend_cap, session_cap,
                idempotency_key, expires_at=None) -> PolicyReservation | None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    f"SELECT {_RES_COLS} FROM reservations WHERE idempotency_key=?", (idempotency_key,)
                ).fetchone()
                if existing is not None:
                    self._conn.commit()
                    return reservation_from_row(existing)

                spend_used = self._conn.execute(
                    _SPEND_USAGE_SQL.format(ph="?"), (engagement_id,)
                ).fetchone()[0] or 0.0
                sessions_used = self._conn.execute(
                    _SESSION_USAGE_SQL.format(ph="?"), (engagement_id,)
                ).fetchone()[0] or 0

                if spend_cap is not None and spend_used + spend > spend_cap:
                    self._conn.rollback()
                    return None
                if session_cap is not None and sessions_used + sessions > session_cap:
                    self._conn.rollback()
                    return None

                res = PolicyReservation(
                    reservation_id=uuid.uuid4().hex, engagement_id=engagement_id, spend=spend,
                    sessions=sessions, spend_final=None, status="reserved",
                    idempotency_key=idempotency_key, expires_at=expires_at,
                    created_at=datetime.now(timezone.utc),
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

    def close(self) -> None:
        with self._lock:
            self._conn.close()
