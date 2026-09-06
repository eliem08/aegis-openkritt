from __future__ import annotations

import json

import pytest

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
    assert record.capability_ids == (
        "tool:semgrep/code", "asset:semgrep/source-static-analysis",
    )
    assert result.summary["covered_capability_ids"] == [
        "tool:semgrep/code", "asset:semgrep/source-static-analysis",
    ]
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


def test_positive_control_miss_is_not_executed_pass(tmp_path):
    def no_findings(argv, timeout):
        return json.dumps({"results": []}), "", 0

    result = execute_tool_fixture(
        "tool:semgrep/code", runs_dir=tmp_path / "runs",
        bridge=ToolBridge(run=no_findings),
    )

    assert result.result is ArsenalCoverageState.BACKEND_UNHEALTHY
    assert result.summary["positive"]["ran"] is True
    assert result.summary["fixture_detection"] is False
    completed = ImmutableRunStore(tmp_path / "runs").events(result.run_id)[-2]
    assert completed.detail["execution_error_class"] == "POSITIVE_CONTROL_MISSED"


def test_negative_control_finding_is_not_executed_pass(tmp_path):
    def findings_on_both(argv, timeout):
        return json.dumps({"results": [{
            "check_id": "aegis.fixture.command-injection",
            "path": "app.py", "start": {"line": 1},
            "extra": {"severity": "ERROR", "message": "fixture sink"},
        }]}), "", 1

    result = execute_tool_fixture(
        "tool:semgrep/code", runs_dir=tmp_path / "runs",
        bridge=ToolBridge(run=findings_on_both),
    )

    assert result.result is ArsenalCoverageState.BACKEND_UNHEALTHY
    assert result.summary["negative_control_passed"] is False
    completed = ImmutableRunStore(tmp_path / "runs").events(result.run_id)[-2]
    assert completed.detail["execution_error_class"] == "NEGATIVE_CONTROL_FAILED"


@pytest.mark.parametrize(
    ("failure", "label"),
    [
        (PermissionError("executable permission denied"), "permission"),
        (TimeoutError("wall-clock limit exceeded"), "timeout"),
        (OSError(8, "exec format error"), "architecture"),
        (MemoryError("memory resource limit"), "resource"),
    ],
)
def test_process_start_failures_never_create_execution_pass(tmp_path, failure, label):
    def fail(_argv, _timeout):
        raise failure

    result = execute_tool_fixture(
        "tool:semgrep/code",
        runs_dir=tmp_path / label,
        bridge=ToolBridge(run=fail),
    )

    assert result.result is ArsenalCoverageState.BACKEND_UNHEALTHY
    assert result.summary["positive"]["ran"] is False
    assert result.summary["negative"]["ran"] is False


@pytest.mark.parametrize(
    "execution",
    [
        ("", "fatal", 2),
        ("", "killed", -9),
        ("not-json", "", 0),
        ('{"results":', "partial output", 0),
    ],
)
def test_nonzero_killed_malformed_and_partial_output_never_pass(tmp_path, execution):
    result = execute_tool_fixture(
        "tool:semgrep/code",
        runs_dir=tmp_path / str(abs(hash(execution))),
        bridge=ToolBridge(run=lambda _argv, _timeout: execution),
    )

    assert result.result is ArsenalCoverageState.BACKEND_UNHEALTHY


def test_output_resource_limit_never_creates_execution_pass(tmp_path):
    result = execute_tool_fixture(
        "tool:semgrep/code",
        runs_dir=tmp_path / "output-limit",
        bridge=ToolBridge(
            run=lambda _argv, _timeout: ("x" * 2048, "", 0),
            max_output_bytes=1024,
        ),
    )

    assert result.result is ArsenalCoverageState.BACKEND_UNHEALTHY
    assert result.summary["positive"]["error"].startswith("OutputLimitExceeded")


def test_parser_crash_never_creates_execution_pass(tmp_path, monkeypatch):
    import aegis.ai.tool_bridge as tool_bridge

    monkeypatch.setattr(
        tool_bridge,
        "_parse",
        lambda _tool, _output: (_ for _ in ()).throw(ValueError("parser crash")),
    )
    result = execute_tool_fixture(
        "tool:semgrep/code",
        runs_dir=tmp_path / "parser-crash",
        bridge=ToolBridge(run=lambda _argv, _timeout: ('{"results": []}', "", 0)),
    )

    assert result.result is ArsenalCoverageState.BACKEND_UNHEALTHY


def test_missing_fixture_is_rejected_before_authorization_or_execution(tmp_path):
    fixture_root = tmp_path / "missing-fixture"
    fixture_root.mkdir()

    with pytest.raises(FileNotFoundError, match="positive and negative"):
        execute_tool_fixture(
            "tool:semgrep/code",
            runs_dir=tmp_path / "runs",
            fixture_root=fixture_root,
            bridge=ToolBridge(run=_controlled_semgrep),
        )

    assert not (tmp_path / "runs").exists()
