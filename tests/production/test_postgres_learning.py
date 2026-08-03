from __future__ import annotations

import os

import pytest

from aegis.learn import Outcome, Verdict
from aegis.production.postgres_learning import PostgresOutcomeStore, PostgresSubmissionLedger

DSN = os.environ.get("AEGIS_TEST_POSTGRES_DSN")


@pytest.mark.skipif(not DSN, reason="set AEGIS_TEST_POSTGRES_DSN to run")
def test_postgres_learning_stores_round_trip_and_are_idempotent():
    pytest.importorskip("psycopg")
    from psycopg_pool import ConnectionPool

    pool = ConnectionPool(DSN, kwargs={"autocommit": True}, open=True)
    try:
        outcomes = PostgresOutcomeStore(pool)
        ledger = PostgresSubmissionLedger(pool)
        with pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute("TRUNCATE learning_outcomes, learning_submissions, learning_recorded")
        outcomes.record(Outcome(detector="d", cwe="CWE-1", verdict=Verdict.CONFIRMED))
        assert outcomes.count() == 1 and outcomes.all()[0].verdict is Verdict.CONFIRMED
        ledger.record_link("r1", detector="d", cwe="CWE-1")
        ledger.record_link("r1", detector="new", cwe="CWE-2")
        assert ledger.get_link("r1")["detector"] == "new"
        ledger.mark_recorded("r1", "resolved", Verdict.CONFIRMED)
        assert ledger.is_recorded("r1")
    finally:
        pool.close()
