from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from aegis.arsenal.ledger import (
    CoverageConflictError,
    CoverageStorageError,
    SqliteCoverageRepository,
)
from aegis.arsenal.models import (
    ArsenalCoverageState,
    CapabilityCoverageRecord,
    CapabilityMode,
)


def coverage() -> CapabilityCoverageRecord:
    return CapabilityCoverageRecord(
        "coverage-1", "idem-1", "tool:semgrep/code", CapabilityMode.FIXTURE,
        "semgrep", "1.2.3", "", ("source_code",), "src/aegis/ai/tool_bridge.py",
        "tool-bridge", "1", "READY", "a" * 64, "fixture://source", "fixture-decision",
        "approval-1", "grant-1", "run-1", "mission-1", "task-1", True,
        datetime.now(UTC).isoformat(), "b" * 64, ArsenalCoverageState.EXECUTED_PASS,
        negative_control_status="PASS",
    )


def test_sqlite_is_forbidden_in_production(tmp_path):
    with pytest.raises(CoverageStorageError, match="forbidden in production"):
        SqliteCoverageRepository(tmp_path / "coverage.db", production=True)


def test_idempotent_concurrent_recording_and_immutable_conflict(tmp_path):
    repository = SqliteCoverageRepository(tmp_path / "coverage.db", production=False)
    value = coverage()

    with ThreadPoolExecutor(max_workers=16) as workers:
        results = list(workers.map(lambda _: repository.record(value), range(16)))

    assert sum(inserted for _record, inserted in results) == 1
    assert len(repository.records()) == 1
    with pytest.raises(CoverageConflictError):
        repository.record(replace(value, backend_version="2"))
    repository.close()


def test_executed_finding_requires_human_reviewed_finding_reference():
    with pytest.raises(ValueError, match="finding IDs"):
        replace(coverage(), result=ArsenalCoverageState.EXECUTED_FINDING)
