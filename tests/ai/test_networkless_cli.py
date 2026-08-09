from __future__ import annotations

from pathlib import Path

import pytest

from aegis.ai.jarvis.asset_cli_executor import CliProcessResult
from aegis.ai.jarvis.asset_deep_capabilities import DeepScannerMethod
from aegis.ai.jarvis.networkless_cli import NetworklessCliError, execute_networkless_cli_method
from aegis.ai.tool_runtime import ToolRuntimeManager


def _method():
    return DeepScannerMethod(
        "scanner",
        "offline",
        ("scanner", "--input", "{artifact}"),
        local_only=True,
        output="json",
    )


def _manager(tmp_path, *, include_bwrap=True):
    scanner = tmp_path / "scanner"
    scanner.write_bytes(b"scanner")
    bwrap = tmp_path / "bwrap"
    if include_bwrap:
        bwrap.write_bytes(b"bwrap")

    def resolver(name):
        if name == "scanner":
            return str(scanner)
        if name == "bwrap" and include_bwrap:
            return str(bwrap)
        return None

    def version(argv, timeout):
        if argv[0] == str(scanner):
            return 0, "scanner 1.0", ""
        if include_bwrap and argv[0] == str(bwrap):
            return 0, "bubblewrap 0.11", ""
        return 1, "", ""

    return ToolRuntimeManager(resolver=resolver, runner=version), scanner, bwrap


def test_networkless_executor_wraps_scanner_in_unshared_read_only_namespace(tmp_path):
    manager, scanner, bwrap = _manager(tmp_path)
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"authorized")
    calls = []

    def process_runner(argv, workspace, timeout, env, maximum_output_bytes):
        calls.append((argv, workspace))
        return CliProcessResult(0, b'{"ok": true}', b"")

    result = execute_networkless_cli_method(
        _method(),
        artifact_path=artifact,
        workspace_root=tmp_path / "work",
        runtime_manager=manager,
        pins={},
        process_runner=process_runner,
    )
    argv, workspace = calls[0]
    assert argv[0] == str(bwrap.resolve())
    assert "--unshare-all" in argv
    assert "--share-net" not in argv
    ro = argv.index("--ro-bind")
    assert argv[ro + 1 : ro + 3] == ["/", "/"]
    bind = argv.index("--bind")
    assert argv[bind + 1 : bind + 3] == [str(workspace), str(workspace)]
    separator = argv.index("--")
    assert argv[separator + 1] == str(scanner.resolve())
    assert argv[separator + 3] == str(artifact.resolve())
    assert result.provenance["network_enforcement"] == "kernel_namespace"
    assert result.provenance["network_sandbox"]["network_shared"] is False
    assert result.provenance["network_sandbox"]["host_root"] == "read_only"


def test_networkless_executor_refuses_missing_bubblewrap_before_scanner_runner(tmp_path):
    manager, _scanner, _bwrap = _manager(tmp_path, include_bwrap=False)
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"authorized")
    calls = []
    with pytest.raises(NetworklessCliError, match="Bubblewrap runtime is unavailable"):
        execute_networkless_cli_method(
            _method(),
            artifact_path=artifact,
            runtime_manager=manager,
            pins={},
            process_runner=lambda *args: calls.append(args) or CliProcessResult(0),
        )
    assert calls == []
