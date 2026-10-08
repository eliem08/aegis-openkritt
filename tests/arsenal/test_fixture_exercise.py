from __future__ import annotations

import json
from pathlib import Path

from aegis.arsenal.exercise import execute_llm_fixture, record_blocked_fixture
from aegis.arsenal.fixture_authority import (
    LocalFixtureSignatureVerifier,
    is_isolated_destination,
    signed_fixture_authorization,
)
from aegis.arsenal.ledger import SqliteCoverageRepository
from aegis.arsenal.llm_lab import CASES
from aegis.arsenal.models import ArsenalCoverageState
from aegis.policy.authorization import Environment
from aegis.policy.signing import HmacSignatureVerifier
from aegis.production.operator_manifest import ImmutableRunStore


def test_fixture_authority_rejects_non_isolated_targets_and_tampered_grants():
    raw = HmacSignatureVerifier({"fixture-auth": b"a" * 32, "grant": b"b" * 32})
    verifier = LocalFixtureSignatureVerifier(raw)
    auth = signed_fixture_authorization(verifier)
    assert auth.environment is Environment.LOCAL_FIXTURE_ONLY
    assert verifier.verify(auth.signing_payload(), auth.signature, auth.signing_key_id)
    escaped = auth.model_copy(update={"targets": ["example.com"]})
    escaped_signature = raw.sign(escaped.signing_payload(), "fixture-auth")
    assert not verifier.verify(escaped.signing_payload(), escaped_signature, "fixture-auth")
    assert is_isolated_destination("http://127.0.0.1:8000")
    assert not is_isolated_destination("https://example.com")


def test_llm_fixture_uses_canonical_runtime_and_records_coverage(tmp_path):
    ledger = SqliteCoverageRepository(tmp_path / "coverage.db")
    result = execute_llm_fixture(runs_dir=tmp_path / "runs", coverage_repository=ledger)
    assert result.result is ArsenalCoverageState.EXECUTED_PASS
    assert result.coverage_recorded is True
    assert result.coverage_recording_degraded is False
    assert result.summary["cases"] == len(CASES) == 16
    assert result.summary["system_boundary_preserved"] == 16
    assert result.summary["p0_bypasses"] == 0
    assert result.summary["authorized_real_ai_execution_coverage"] is None
    records = ledger.records()
    assert len(records) == 1
    assert records[0].negative_control_status == "PASSED"
    verification = ImmutableRunStore(tmp_path / "runs").verify(result.run_id)
    assert verification["last_status"] == "completed"
    ledger.close()


class _OutageRepository:
    def record(self, value):
        raise ConnectionError("coverage PostgreSQL unavailable")


def test_ledger_outage_degrades_projection_but_not_canonical_execution(tmp_path):
    result = execute_llm_fixture(
        runs_dir=tmp_path / "runs", coverage_repository=_OutageRepository(),
    )
    assert result.result is ArsenalCoverageState.EXECUTED_PASS
    assert result.coverage_recorded is False
    assert result.coverage_recording_degraded is True
    events = ImmutableRunStore(tmp_path / "runs").events(result.run_id)
    assert events[-1].event_type == "coverage_recording_degraded"
    assert events[-1].detail["execution_result_remains_canonical"] is True


def test_executed_finding_is_not_awarded_by_fixture_lab(tmp_path):
    result = execute_llm_fixture(runs_dir=tmp_path / "runs")
    assert result.result is ArsenalCoverageState.EXECUTED_PASS
    assert result.summary["model_behavior_unsafe"] == 16
    assert "finding" not in result.result.value.casefold()


def test_missing_fixture_backend_stops_before_grant_and_execution(tmp_path):
    ledger = SqliteCoverageRepository(tmp_path / "coverage.db")
    result = record_blocked_fixture(
        "asset:frida/android-runtime-instrumentation",
        state_value=ArsenalCoverageState.WAITING_FOR_PREREQUISITE,
        reason="local Android emulator and operator-owned fixture app are required",
        runs_dir=tmp_path / "runs", coverage_repository=ledger,
    )

    assert result.result is ArsenalCoverageState.WAITING_FOR_PREREQUISITE
    assert result.summary["execution_performed"] is False
    evidence = json.loads(Path(
        tmp_path / "runs" / result.run_id / result.evidence_ref
    ).read_text(encoding="utf-8"))
    assert evidence["execution_grant_issued"] is False
    record = ledger.records()[0]
    assert record.executed is False
    assert record.execution_grant_id is None
    ledger.close()
