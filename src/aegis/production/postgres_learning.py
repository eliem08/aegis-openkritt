"""PostgreSQL-backed learning outcomes and submission links."""

from __future__ import annotations

from aegis.learn.hackerone_sync import SubmissionLedger
from aegis.learn.store import Outcome, OutcomeStore, Verdict

SCHEMA = """
CREATE TABLE IF NOT EXISTS learning_outcomes (
    outcome_id BIGSERIAL PRIMARY KEY, detector TEXT, cwe TEXT, verdict TEXT,
    fingerprint TEXT, asset TEXT, program TEXT, summary TEXT, created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_learning_outcomes_created ON learning_outcomes(created_at);
CREATE TABLE IF NOT EXISTS learning_submissions (
    report_id TEXT PRIMARY KEY, detector TEXT, cwe TEXT, fingerprint TEXT,
    asset TEXT, program TEXT, summary TEXT
);
CREATE TABLE IF NOT EXISTS learning_recorded (
    report_id TEXT PRIMARY KEY, state TEXT, verdict TEXT
);
"""


class PostgresOutcomeStore(OutcomeStore):
    """OutcomeStore protocol implemented on the control plane's shared pool."""

    def __init__(self, pool):
        self._pool = pool
        self._exec(SCHEMA)

    def _exec(self, sql, params=()):
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(sql, params)

    def _query(self, sql, params=()):
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(sql, params)
            return cursor.fetchall()

    def record(self, outcome: Outcome) -> None:
        self._exec(
            "INSERT INTO learning_outcomes "
            "(detector,cwe,verdict,fingerprint,asset,program,summary,created_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            (outcome.detector, outcome.cwe, Verdict(outcome.verdict).value,
             outcome.fingerprint, outcome.asset, outcome.program, outcome.summary,
             outcome.created_at),
        )

    def all(self) -> list[Outcome]:
        rows = self._query(
            "SELECT detector,cwe,verdict,fingerprint,asset,program,summary,created_at "
            "FROM learning_outcomes ORDER BY created_at,outcome_id"
        )
        return [Outcome(
            detector=row[0], cwe=row[1], verdict=Verdict(row[2]), fingerprint=row[3],
            asset=row[4], program=row[5], summary=row[6], created_at=row[7],
        ) for row in rows]

    def count(self) -> int:
        return int(self._query("SELECT COUNT(*) FROM learning_outcomes")[0][0])

    def close(self) -> None:
        pass


class PostgresSubmissionLedger(SubmissionLedger):
    def __init__(self, pool):
        self._pool = pool
        self._exec(SCHEMA)

    def _exec(self, sql, params=()):
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(sql, params)

    def _query_one(self, sql, params=()):
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(sql, params)
            return cursor.fetchone()

    def record_link(self, report_id: str, *, detector: str = "", cwe: str = "",
                    fingerprint: str = "", asset: str = "", program: str = "",
                    summary: str = "") -> None:
        self._exec(
            "INSERT INTO learning_submissions "
            "(report_id,detector,cwe,fingerprint,asset,program,summary) VALUES (%s,%s,%s,%s,%s,%s,%s) "
            "ON CONFLICT (report_id) DO UPDATE SET detector=EXCLUDED.detector,cwe=EXCLUDED.cwe,"
            "fingerprint=EXCLUDED.fingerprint,asset=EXCLUDED.asset,program=EXCLUDED.program,summary=EXCLUDED.summary",
            (str(report_id), detector, cwe, fingerprint, asset, program, summary[:240]),
        )

    def get_link(self, report_id: str) -> dict | None:
        row = self._query_one(
            "SELECT detector,cwe,fingerprint,asset,program,summary FROM learning_submissions WHERE report_id=%s",
            (str(report_id),),
        )
        if row is None:
            return None
        return dict(detector=row[0], cwe=row[1], fingerprint=row[2], asset=row[3], program=row[4], summary=row[5])

    def is_recorded(self, report_id: str) -> bool:
        return self._query_one(
            "SELECT 1 FROM learning_recorded WHERE report_id=%s", (str(report_id),),
        ) is not None

    def mark_recorded(self, report_id: str, state: str, verdict: Verdict) -> None:
        self._exec(
            "INSERT INTO learning_recorded (report_id,state,verdict) VALUES (%s,%s,%s) "
            "ON CONFLICT (report_id) DO UPDATE SET state=EXCLUDED.state,verdict=EXCLUDED.verdict",
            (str(report_id), state, Verdict(verdict).value),
        )

    def close(self) -> None:
        pass
