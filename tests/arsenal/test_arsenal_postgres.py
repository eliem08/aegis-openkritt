from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from aegis.arsenal.ledger import CoverageConflictError, PostgresCoverageRepository
from aegis.arsenal.models import (
    ArsenalCoverageState,
    CapabilityCoverageRecord,
    CapabilityMode,
)

DSN = os.environ.get("AEGIS_TEST_POSTGRES_DSN")


def coverage() -> CapabilityCoverageRecord:
    return CapabilityCoverageRecord(
        "coverage-postgres", "idem-postgres", "tool:semgrep/code", CapabilityMode.FIXTURE,
        "semgrep", "1.2.3", "", ("source_code",), "src/aegis/ai/tool_bridge.py",
        "tool-bridge", "1", "READY", "a" * 64, "127.0.0.1", "fixture-decision",
        None, "grant-1", "run-1", "mission-1", "task-1", True,
        datetime.now(UTC).isoformat(), "b" * 64, ArsenalCoverageState.EXECUTED_PASS,
        negative_control_status="PASSED",
    )


@pytest.mark.skipif(not DSN, reason="set AEGIS_TEST_POSTGRES_DSN to run")
def test_postgres_coverage_is_exactly_once_concurrent_and_immutable():
    pytest.importorskip("psycopg")
    setup = PostgresCoverageRepository(DSN)
    with setup._connection.cursor() as cursor:
        cursor.execute("TRUNCATE arsenal_coverage_records")
    setup._connection.commit()
    setup.close()
    item = coverage()

    def record(_):
        repository = PostgresCoverageRepository(DSN)
        try:
            return repository.record(item)[1]
        finally:
            repository.close()

    with ThreadPoolExecutor(max_workers=8) as workers:
        inserted = list(workers.map(record, range(16)))
    assert inserted.count(True) == 1
    assert inserted.count(False) == 15

    repository = PostgresCoverageRepository(DSN)
    assert repository.records() == (item,)
    with pytest.raises(CoverageConflictError):
        repository.record(replace(item, backend_version="mutated"))
    with repository._connection.cursor() as cursor:
        with pytest.raises(Exception, match="immutable coverage"):
            cursor.execute(
                "UPDATE arsenal_coverage_records SET backend_version='mutated' "
                "WHERE coverage_record_id=%s", (item.coverage_record_id,),
            )
    repository._connection.rollback()
    repository.close()
