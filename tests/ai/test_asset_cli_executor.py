from __future__ import annotations

from pathlib import Path

import pytest

from aegis.ai.jarvis.asset_cli_executor import (
    CliProcessResult,
    LocalCliExecutionError,
    cleanup_local_cli_execution,
    execute_local_cli_method,
)
from aegis.ai.jarvis.asset_deep_capabilities import DeepScannerMethod
from aegis.ai.tool_runtime import ToolRuntimeManager


def _manager(tmp_path):
    binary = tmp_path / "scanner"
    binary.write_bytes(b"scanner-binary")
    manager = ToolRuntimeManager(
        resolver=lambda _name: str(binary),
        runner=lambda argv, timeout: (0, "scanner 1.0", ""),
    )
    return manager, binary


def _offline_method():
    return DeepScannerMethod(
        "scanner",
        "offline-static",
        ("scanner", "--input", "{artifact}", "--output", "{output}"),
        local_only=True,
        output="json",
    )


def test_executor_uses_ready_exact_binary_argv_and_sanitized_env(tmp_path, monkeypatch):
    manager, binary = _manager(tmp_path)
    artifact = tmp_path / "sample.apk"
    artifact.write_bytes(b"authorized")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-leak")
    monkeypatch.setenv("HTTPS_PROXY", "http://corporate-proxy:8080")
    calls = []

    def runner(argv, workspace, timeout, env, maximum_output_bytes):
        calls.append((argv, workspace, env))
        output_index = argv.index("--output") + 1
        Path(argv[output_index]).write_text('{"ok": true}', encoding="utf-8")
        return CliProcessResult(0, b'{"candidate": 1}', b"")

    result = execute_local_cli_method(
        _offline_method(),
        artifact_path=artifact,
        workspace_root=tmp_path / "work",
        runtime_manager=manager,
        pins={},
        runner=runner,
    )
    argv, workspace, env = calls[0]
    assert argv[0] == str(binary.resolve())
    assert argv[2] == str(artifact.resolve())
    assert isinstance(argv, list)
    assert "GITHUB_TOKEN" not in env
    assert env["HTTPS_PROXY"] == "http://127.0.0.1:9"
    assert result.ok is True
    assert result.provenance["shell"] is False
    assert result.provenance["binary_sha256"]
    assert result.output_file == b'{"ok": true}'
    assert result.workspace == ""
    assert not workspace.exists()


def test_executor_blocks_network_state_change_and_non_local_before_runner(tmp_path):
    manager, _binary = _manager(tmp_path)
    calls = []

    def runner(*args):
        calls.append(args)
        return CliProcessResult(0)

    network = DeepScannerMethod(
        "scanner", "network", ("scanner", "{target}"),
        local_only=True, requires_network=True,
    )
    with pytest.raises(LocalCliExecutionError, match="network-capable"):
        execute_local_cli_method(
            network, target_path=tmp_path, runtime_manager=manager, pins={}, runner=runner
        )

    changing = DeepScannerMethod(
        "scanner", "changing", ("scanner", "{artifact}"),
        local_only=True, state_change_possible=True,
    )
    artifact = tmp_path / "a.bin"
    artifact.write_bytes(b"x")
    with pytest.raises(LocalCliExecutionError, match="state-changing"):
        execute_local_cli_method(
            changing, artifact_path=artifact, runtime_manager=manager, pins={}, runner=runner
        )

    nonlocal_method = DeepScannerMethod("scanner", "not-local", ("scanner", "{artifact}"))
    with pytest.raises(LocalCliExecutionError, match="local_only"):
        execute_local_cli_method(
            nonlocal_method, artifact_path=artifact,
            runtime_manager=manager, pins={}, runner=runner,
        )
    assert calls == []


def test_executor_rejects_missing_inputs_unknown_placeholders_and_unhealthy_runtime(tmp_path):
    manager, _binary = _manager(tmp_path)
    with pytest.raises(LocalCliExecutionError, match="missing local input"):
        execute_local_cli_method(_offline_method(), runtime_manager=manager, pins={})

    artifact = tmp_path / "a.apk"
    artifact.write_bytes(b"x")
    unknown = DeepScannerMethod(
        "scanner", "bad-template", ("scanner", "{endpoint}"), local_only=True
    )
    with pytest.raises(LocalCliExecutionError, match="unsupported command placeholder"):
        execute_local_cli_method(
            unknown, artifact_path=artifact, runtime_manager=manager, pins={}
        )

    unavailable = ToolRuntimeManager(resolver=lambda _name: None)
    with pytest.raises(LocalCliExecutionError, match="unavailable"):
        execute_local_cli_method(
            _offline_method(), artifact_path=artifact,
            runtime_manager=unavailable, pins={},
        )


def test_retained_workspace_manifest_and_explicit_cleanup(tmp_path):
    manager, _binary = _manager(tmp_path)
    artifact = tmp_path / "a.apk"
    artifact.write_bytes(b"x")
    method = DeepScannerMethod(
        "scanner",
        "extract",
        ("scanner", "--input", "{artifact}", "--dir", "{output_dir}"),
        local_only=True,
        output="directory",
    )

    def runner(argv, workspace, timeout, env, maximum_output_bytes):
        out = Path(argv[argv.index("--dir") + 1])
        (out / "nested").mkdir(parents=True)
        (out / "nested" / "manifest.xml").write_text("<manifest/>", encoding="utf-8")
        return CliProcessResult(0, b"done", b"")

    result = execute_local_cli_method(
        method,
        artifact_path=artifact,
        workspace_root=tmp_path / "work",
        retain_workspace=True,
        runtime_manager=manager,
        pins={},
        runner=runner,
    )
    assert result.retained_workspace is True
    assert Path(result.workspace).is_dir()
    assert any(item.relative_path == "output/nested/manifest.xml" for item in result.outputs)
    assert all(item.sha256 for item in result.outputs)
    cleanup_local_cli_execution(result)
    assert not Path(result.workspace).exists()


def test_nonexistent_path_is_rejected_before_runtime_probe(tmp_path):
    manager, _binary = _manager(tmp_path)
    with pytest.raises(LocalCliExecutionError, match="existing local path"):
        execute_local_cli_method(
            _offline_method(),
            artifact_path=tmp_path / "missing.apk",
            runtime_manager=manager,
            pins={},
        )
