from __future__ import annotations

import json
from pathlib import Path

from aegis.ai.jarvis.ai_model_pipeline import run_ai_model_pipeline
from aegis.ai.jarvis.asset_cli_executor import CliProcessResult
from aegis.ai.tool_runtime import ToolRuntimeManager


def _model(tmp_path):
    model = tmp_path / "demo.pkl"
    model.write_bytes(b"\x80\x04authorized-model")
    return model


def _manager(tmp_path, *, modelscan=True, bwrap=True):
    binaries = {}
    if modelscan:
        path = tmp_path / "modelscan"
        path.write_bytes(b"modelscan")
        binaries["modelscan"] = path
    if bwrap:
        path = tmp_path / "bwrap"
        path.write_bytes(b"bwrap")
        binaries["bwrap"] = path

    def resolver(name):
        path = binaries.get(name)
        return str(path) if path is not None else None

    def version(argv, timeout):
        name = Path(argv[0]).name
        if name in binaries:
            return 0, f"{name} 1.0", ""
        return 1, "", ""

    return ToolRuntimeManager(resolver=resolver, runner=version), binaries


def test_pipeline_modelscan_exit_one_is_successful_unverified_candidate(tmp_path):
    model = _model(tmp_path)
    manager, binaries = _manager(tmp_path)
    calls = []
    payload = {
        "issues": [
            {
                "description": "Use of unsafe operator 'system'",
                "operator": "system",
                "module": "pickle",
                "source": "demo.pkl",
                "scanner": "PickleUnsafeOpScan",
                "severity": "CRITICAL",
            }
        ]
    }

    def process_runner(argv, workspace, timeout, env, maximum_output_bytes):
        calls.append(argv)
        scanner = argv[argv.index("--") + 1 :]
        assert scanner[0] == str(binaries["modelscan"].resolve())
        assert scanner[scanner.index("-p") + 1] == str(model.resolve())
        output = Path(scanner[scanner.index("-o") + 1])
        output.write_text(json.dumps(payload), encoding="utf-8")
        return CliProcessResult(1, b"", b"")

    report = run_ai_model_pipeline(
        model,
        scope_digest="scope:model",
        workspace_root=tmp_path / "work",
        runtime_manager=manager,
        pins={},
        process_runner=process_runner,
    )
    assert {stage.stage: stage.status for stage in report.stages} == {
        "provenance": "complete",
        "modelscan": "complete",
    }
    assert report.engine_errors == {}
    assert report.provenance.format == "pickle_protocol"
    assert report.provenance.deserialized is False
    assert len(report.candidates) == 1
    row = report.candidates[0]
    assert row["source"] == "aegis:tool:modelscan"
    assert row["validation_status"] == "unverified"
    assert row["model_artifact"]["sha256"] == report.artifact_ticket.sha256
    assert row["model_artifact"]["deserialized"] is False
    assert report.observations[0].kind == "ai_model_provenance"
    assert report.observations[0].data["deserialized"] is False
    assert calls[0][0] == str(binaries["bwrap"].resolve())
    assert "--unshare-all" in calls[0]
    assert "--share-net" not in calls[0]


def test_modelscan_exit_two_is_partial_failure_not_clean_scan(tmp_path):
    model = _model(tmp_path)
    manager, _binaries = _manager(tmp_path)

    def process_runner(argv, workspace, timeout, env, maximum_output_bytes):
        scanner = argv[argv.index("--") + 1 :]
        output = Path(scanner[scanner.index("-o") + 1])
        output.write_text(
            json.dumps(
                {
                    "issues": [
                        {
                            "description": "stale output must not promote",
                            "operator": "exec",
                            "module": "pickle",
                            "source": "demo.pkl",
                            "scanner": "pickle",
                            "severity": "HIGH",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return CliProcessResult(2, b"", b"error")

    report = run_ai_model_pipeline(
        model,
        scope_digest="scope:model",
        runtime_manager=manager,
        pins={},
        process_runner=process_runner,
    )
    statuses = {stage.stage: stage.status for stage in report.stages}
    assert statuses["provenance"] == "complete"
    assert statuses["modelscan"] == "failed"
    assert report.candidates == []
    assert "unsuccessful exit code 2" in report.engine_errors["modelscan"]


def test_missing_bubblewrap_or_modelscan_preserves_provenance_and_records_engine_failure(tmp_path):
    for missing in ("bwrap", "modelscan"):
        model = _model(tmp_path)
        manager, _binaries = _manager(
            tmp_path,
            modelscan=missing != "modelscan",
            bwrap=missing != "bwrap",
        )
        report = run_ai_model_pipeline(
            model,
            scope_digest="scope:model",
            runtime_manager=manager,
            pins={},
        )
        statuses = {stage.stage: stage.status for stage in report.stages}
        assert statuses["provenance"] == "complete"
        assert statuses["modelscan"] == "failed"
        assert report.candidates == []
        assert "modelscan" in report.engine_errors


def test_model_mutation_during_modelscan_blocks_candidate_promotion(tmp_path):
    model = _model(tmp_path)
    manager, _binaries = _manager(tmp_path)
    payload = {
        "issues": [
            {
                "description": "candidate",
                "operator": "system",
                "module": "pickle",
                "source": "demo.pkl",
                "scanner": "pickle",
                "severity": "HIGH",
            }
        ]
    }

    def process_runner(argv, workspace, timeout, env, maximum_output_bytes):
        scanner = argv[argv.index("--") + 1 :]
        output = Path(scanner[scanner.index("-o") + 1])
        output.write_text(json.dumps(payload), encoding="utf-8")
        model.write_bytes(model.read_bytes() + b"tamper")
        return CliProcessResult(1, b"", b"")

    report = run_ai_model_pipeline(
        model,
        scope_digest="scope:model",
        runtime_manager=manager,
        pins={},
        process_runner=process_runner,
    )
    assert {stage.stage: stage.status for stage in report.stages}["modelscan"] == "failed"
    assert report.candidates == []
    assert "changed during ModelScan" in report.engine_errors["modelscan"]


def test_modelscan_can_be_disabled_without_affecting_provenance(tmp_path):
    model = _model(tmp_path)
    report = run_ai_model_pipeline(
        model,
        scope_digest="scope:model",
        run_modelscan=False,
    )
    assert {stage.stage: stage.status for stage in report.stages} == {
        "provenance": "complete",
        "modelscan": "skipped",
    }
    assert report.candidates == []
