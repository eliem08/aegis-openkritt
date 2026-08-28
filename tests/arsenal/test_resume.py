from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

from aegis.arsenal.models import (
    ArsenalCoverageState,
    CapabilityCoverageRecord,
    CapabilityMode,
    ExecutionProofKind,
    HistoricalExecution,
)
from aegis.arsenal.resume import resumable_record


def _record() -> CapabilityCoverageRecord:
    return CapabilityCoverageRecord(
        "coverage-1", "idem-1", "cap:a", CapabilityMode.FIXTURE, "tool", "1.0",
        "", ("source_code",), "implementation", "backend", "adapter/1", "HEALTHY",
        "a" * 64, "fixture://source", "decision", None, "grant", "run", "mission",
        "task", True, datetime.now(UTC).isoformat(), "b" * 64,
        ArsenalCoverageState.EXECUTED_PASS, negative_control_status="PASSED",
    )


def _history(record):
    return HistoricalExecution(
        record.capability_id, record.mode, record.result, record.run_id,
        record.mission_id, record.task_id, record.backend, record.backend_version,
        record.policy_snapshot_digest, record.asset, record.authorization_decision,
        record.operator_approval_id, record.execution_grant_id,
        str(record.execution_timestamp), str(record.evidence_digest),
    )


def test_resume_requires_matching_versions_fixture_and_verified_evidence() -> None:
    record = replace(
        _record(), result=ArsenalCoverageState.EXECUTED_PASS,
        schema_version=2, backend_execution_id="exec-1", binary_path="/bin/tool",
        adapter_version="adapter/1", capability_ids=("cap:a",),
        fixture_version="fixture/1", positive_fixture_digest="a" * 64,
        negative_fixture_digest="b" * 64, execution_started_at="2026-01-01T00:00:00Z",
        execution_completed_at="2026-01-01T00:00:01Z", stdout_digest="c" * 64,
        stderr_digest="d" * 64, parsed_result_digest="e" * 64,
        positive_control_detected=True, negative_control_clean=True,
        execution_proof_kind=ExecutionProofKind.REAL_BACKEND,
    )
    assert resumable_record(
        (record,), (_history(record),), capability_id=record.capability_id,
        tool_version=record.tool_version, adapter_version="adapter/1",
        fixture_version="fixture/1",
    ) == record
    assert resumable_record(
        (record,), (_history(record),), capability_id=record.capability_id,
        tool_version="changed", adapter_version="adapter/1", fixture_version="fixture/1",
    ) is None
    assert resumable_record(
        (record,), (), capability_id=record.capability_id,
        tool_version=record.tool_version, adapter_version="adapter/1",
        fixture_version="fixture/1",
    ) is None
