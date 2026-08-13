from __future__ import annotations

import json

from aegis.ai.tool_bridge import ToolBridge
from aegis.arsenal.ledger import SqliteCoverageRepository
from aegis.arsenal.models import ArsenalCoverageState
from aegis.arsenal.tool_exercise import execute_tool_fixture
from aegis.production.operator_manifest import ImmutableRunStore


def _controlled_semgrep(argv, timeout):
    target = argv[-1].replace("\\", "/")
    if target.endswith("/positive"):
        return json.dumps({"results": [{
            "check_id": "aegis.fixture.command-injection",
            "path": "app.py", "start": {"line": 5},
            "extra": {"severity": "ERROR", "message": "fixture sink"},
        }]}), "", 1
    return json.dumps({"results": []}), "", 0


def test_tool_fixture_runs_positive_and_negative_through_runtime(tmp_path):
    ledger = SqliteCoverageRepository(tmp_path / "coverage.db")
    result = execute_tool_fixture(
        "tool:semgrep/code", runs_dir=tmp_path / "runs", coverage_repository=ledger,
        bridge=ToolBridge(run=_controlled_semgrep),
    )
    assert result.result is ArsenalCoverageState.EXECUTED_PASS
    assert result.summary["fixture_detection"] is True
    assert result.summary["negative_control_passed"] is True
    assert result.coverage_recorded is True
    record = ledger.records()[0]
    assert record.result is ArsenalCoverageState.EXECUTED_PASS
    assert record.finding_ids == ()
    assert record.negative_control_status == "PASSED"
    assert ImmutableRunStore(tmp_path / "runs").verify(result.run_id)["last_status"] == "completed"
    ledger.close()


def test_tool_crash_is_backend_unhealthy_not_executed_pass(tmp_path):
    def crash(argv, timeout):
        raise TimeoutError("fixture timeout")

    result = execute_tool_fixture(
        "tool:semgrep/code", runs_dir=tmp_path / "runs", bridge=ToolBridge(run=crash),
    )
    assert result.result is ArsenalCoverageState.BACKEND_UNHEALTHY
    assert result.summary["positive"]["ran"] is False
    assert result.summary["negative"]["ran"] is False
