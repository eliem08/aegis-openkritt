from __future__ import annotations

from pathlib import Path

import pytest

from aegis.ai.jarvis.android_static import (
    ANDROID_APKTOOL,
    ANDROID_JADX,
    AndroidStaticError,
    cleanup_android_static,
    execute_android_static,
    issue_android_static_ticket,
)
from aegis.ai.jarvis.asset_cli_executor import CliProcessResult
from aegis.ai.jarvis.asset_execution_ticket import AssetExecutionTicketError
from aegis.ai.tool_runtime import ToolRuntimeManager


def _manager(tmp_path, tool):
    scanner = tmp_path / tool
    scanner.write_bytes(tool.encode())
    bwrap = tmp_path / "bwrap"
    bwrap.write_bytes(b"bwrap")

    def resolver(name):
        if name == tool:
            return str(scanner)
        if name == "bwrap":
            return str(bwrap)
        return None

    def version(argv, timeout):
        if argv[0] == str(scanner):
            return 0, f"{tool} 1.0", ""
        if argv[0] == str(bwrap):
            return 0, "bubblewrap 0.11", ""
        return 1, "", ""

    return ToolRuntimeManager(resolver=resolver, runner=version), scanner, bwrap


def _apk(tmp_path):
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04authorized-apk")
    return apk


def test_jadx_ticket_binds_apk_and_networkless_decompile_tree(tmp_path):
    apk = _apk(tmp_path)
    manager, scanner, bwrap = _manager(tmp_path, "jadx")
    calls = []

    def process_runner(argv, workspace, timeout, env, maximum_output_bytes):
        calls.append(argv)
        separator = argv.index("--")
        scanner_argv = argv[separator + 1 :]
        assert scanner_argv[0] == str(scanner.resolve())
        output = Path(scanner_argv[scanner_argv.index("-d") + 1])
        output.mkdir(parents=True, exist_ok=True)
        (output / "sources/com/example").mkdir(parents=True)
        (output / "sources/com/example/MainActivity.java").write_text(
            "class MainActivity {}", encoding="utf-8"
        )
        (output / "resources/AndroidManifest.xml").parent.mkdir(parents=True)
        (output / "resources/AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
        return CliProcessResult(0, b"done", b"")

    ticket = issue_android_static_ticket(apk, ANDROID_JADX, scope_digest="scope:android")
    outcome = execute_android_static(
        apk,
        ANDROID_JADX,
        ticket=ticket,
        scope_digest="scope:android",
        workspace_root=tmp_path / "work",
        runtime_manager=manager,
        pins={},
        process_runner=process_runner,
    )
    try:
        assert outcome.candidates == ()
        assert outcome.observation["kind"] == "android_derived_source"
        assert outcome.observation["network_enforcement"] == "kernel_namespace"
        assert outcome.derived_tree.file_count == 2
        assert len(outcome.derived_tree.tree_digest) == 64
        assert Path(outcome.derived_tree.root).is_dir()
        assert calls[0][0] == str(bwrap.resolve())
        assert "--unshare-all" in calls[0]
        assert "--share-net" not in calls[0]
    finally:
        cleanup_android_static(outcome.derived_tree)
    assert not Path(outcome.derived_tree.root).exists()


def test_apktool_uses_same_static_ticket_and_networkless_boundary(tmp_path):
    apk = _apk(tmp_path)
    manager, scanner, _bwrap = _manager(tmp_path, "apktool")

    def process_runner(argv, workspace, timeout, env, maximum_output_bytes):
        scanner_argv = argv[argv.index("--") + 1 :]
        assert scanner_argv[0] == str(scanner.resolve())
        output = Path(scanner_argv[scanner_argv.index("-o") + 1])
        output.mkdir(parents=True, exist_ok=True)
        (output / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
        (output / "smali").mkdir()
        (output / "smali/Main.smali").write_text(".class public LMain;", encoding="utf-8")
        return CliProcessResult(0, b"done", b"")

    ticket = issue_android_static_ticket(apk, ANDROID_APKTOOL, scope_digest="scope:android")
    outcome = execute_android_static(
        apk,
        ANDROID_APKTOOL,
        ticket=ticket,
        scope_digest="scope:android",
        runtime_manager=manager,
        pins={},
        process_runner=process_runner,
    )
    try:
        assert outcome.derived_tree.file_count == 2
        assert outcome.derived_tree.runtime_provenance["network_sandbox"]["network_shared"] is False
    finally:
        cleanup_android_static(outcome.derived_tree)


def test_ticket_rejects_non_apk_and_apk_mutation_before_runner(tmp_path):
    bad = tmp_path / "app.zip"
    bad.write_bytes(b"PK\x03\x04")
    with pytest.raises(AndroidStaticError, match=".apk artifacts only"):
        issue_android_static_ticket(bad, ANDROID_JADX, scope_digest="scope:android")

    apk = _apk(tmp_path)
    manager, _scanner, _bwrap = _manager(tmp_path, "jadx")
    ticket = issue_android_static_ticket(apk, ANDROID_JADX, scope_digest="scope:android")
    apk.write_bytes(apk.read_bytes() + b"tampered")
    calls = []
    with pytest.raises(AndroidStaticError, match="digest changed"):
        execute_android_static(
            apk,
            ANDROID_JADX,
            ticket=ticket,
            scope_digest="scope:android",
            runtime_manager=manager,
            pins={},
            process_runner=lambda *args: calls.append(args) or CliProcessResult(0),
        )
    assert calls == []


def test_scanner_specific_ticket_cannot_be_reused_for_other_decompiler(tmp_path):
    apk = _apk(tmp_path)
    ticket = issue_android_static_ticket(apk, ANDROID_JADX, scope_digest="scope:android")
    with pytest.raises(AndroidStaticError, match="method mismatch"):
        execute_android_static(
            apk,
            ANDROID_APKTOOL,
            ticket=ticket,
            scope_digest="scope:android",
        )


def test_derived_symlink_is_rejected_and_workspace_cleaned(tmp_path):
    apk = _apk(tmp_path)
    manager, _scanner, _bwrap = _manager(tmp_path, "jadx")

    def process_runner(argv, workspace, timeout, env, maximum_output_bytes):
        scanner_argv = argv[argv.index("--") + 1 :]
        output = Path(scanner_argv[scanner_argv.index("-d") + 1])
        output.mkdir(parents=True, exist_ok=True)
        try:
            (output / "escape").symlink_to("/etc/passwd")
        except OSError:
            pytest.skip("symlink creation unavailable")
        return CliProcessResult(0, b"done", b"")

    ticket = issue_android_static_ticket(apk, ANDROID_JADX, scope_digest="scope:android")
    with pytest.raises(AndroidStaticError, match="contains a symlink"):
        execute_android_static(
            apk,
            ANDROID_JADX,
            ticket=ticket,
            scope_digest="scope:android",
            workspace_root=tmp_path / "work",
            runtime_manager=manager,
            pins={},
            process_runner=process_runner,
        )
    assert not list((tmp_path / "work").glob("aegis-asset-*"))


def test_unregistered_android_static_method_is_refused(tmp_path):
    from aegis.ai.jarvis.asset_deep_capabilities import DeepScannerMethod

    apk = _apk(tmp_path)
    method = DeepScannerMethod("unknown", "decode", ("unknown", "{artifact}"), local_only=True)
    with pytest.raises(AssetExecutionTicketError, match="not a registered Android"):
        issue_android_static_ticket(apk, method, scope_digest="scope:android")
