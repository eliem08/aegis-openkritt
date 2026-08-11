from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from aegis.effectiveness.postgres import PostgresEffectivenessRepository

from .helpers import fact, outcome, subject

DSN = os.environ.get("AEGIS_TEST_POSTGRES_DSN")


@pytest.mark.skipif(not DSN, reason="set AEGIS_TEST_POSTGRES_DSN to run")
def test_postgres_concurrent_outcome_is_exactly_once_and_immutable():
    pytest.importorskip("psycopg")
    repository = PostgresEffectivenessRepository(DSN)
    with repository._pool.connection() as connection, connection.cursor() as cursor:
        cursor.execute(
            "TRUNCATE effectiveness_shadow_entries,effectiveness_shadow_batches,"
            "effectiveness_outcome_events,effectiveness_facts,effectiveness_subjects CASCADE"
        )
    item = subject()
    repository.record_subject(item, (fact(item),))
    recorded_outcome = outcome(item)

    def record(_):
        return repository.record_outcome(recorded_outcome)[1]

    with ThreadPoolExecutor(max_workers=8) as pool:
        inserted = list(pool.map(record, range(16)))
    assert inserted.count(True) == 1
    assert inserted.count(False) == 15
    assert len(repository.latest_outcomes()) == 1
    with repository._pool.connection() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="immutable effectiveness ledger"):
            cursor.execute(
                "UPDATE effectiveness_outcome_events SET state='duplicate' "
                "WHERE subject_id=%s", (item.subject_id,),
            )
    repository.close()
