from __future__ import annotations

from pathlib import Path

import pytest

from aegis.ai.jarvis.asset_capabilities import AssetKind
from aegis.ai.jarvis.asset_deep_capabilities import GHIDRA
from aegis.ai.jarvis.asset_execution_ticket import (
    CapabilityAvailability,
    issue_offline_execution_ticket,
)
from aegis.ai.jarvis.ghidra_sandbox import (
    GhidraSandboxError,
    GhidraSandboxProcessResult,
    execute_ghidra_sandboxed,
)
from aegis.ai.tool_runtime import ToolRuntimeManager


def _install(tmp_path, *, metadata=True):
    root = tmp_path / "ghidra"
    launcher = root / "support" / "analyzeHeadless"
    launcher.parent.mkdir(parents=True)
    launcher.write_bytes(b"#!/bin/sh\n")
    app = root / "Ghidra" / "application.properties"
    if metadata:
        app.parent.mkdir(parents=True)
        app.write_text(
            "application.version=12.0.4\napplication.release.name=PUBLIC\n",
            encoding="utf-8",
        )
    bwrap = tmp_path / "bwrap"
    bwrap.write_bytes(b"bubblewrap")
    return launcher, bwrap


def _ticket():
    return issue_offline_execution_ticket(
        asset_kind=AssetKind.EXECUTABLE,
        method=GHIDRA,
        scope_digest="scope:ghidra",
        availability=CapabilityAvailability(
            artifact_available=True,
            sandbox_available=True,
        ),
    )


def _manager(launcher: Path, bwrap: Path):
    def resolve(name):
        if name == "analyzeHeadless":
            return str(launcher)
        if name == "bwrap":
            return str(bwrap)
        return None

    def version(argv, timeout):
        if argv[0] == str(bwrap):
            return 0, "bubblewrap 0.11.0", ""
        raise AssertionError("Ghidra version must come from install metadata")

    return ToolRuntimeManager(resolver=resolve, runner=version)


def test_ghidra_runs_inside_unshared_read_only_bubblewrap_namespace(tmp_path):
    launcher, bwrap = _install(tmp_path)
    artifact = tmp_path / "sample.bin"
    artifact.write_bytes(b"authorized")
    manager = _manager(launcher, bwrap)
    calls = []

    def runner(argv, workspace, timeout, env, maximum_output_bytes):
        calls.append((argv, workspace, env))
        (workspace / "ghidra.log").write_text("analysis complete", encoding="utf-8")
        return GhidraSandboxProcessResult(0, b"ok", b"")

    result = execute_ghidra_sandboxed(
        artifact_path=artifact,
        ticket=_ticket(),
        workspace_root=tmp_path / "work",
        retain_workspace=True,
        runtime_manager=manager,
        pins={},
        runner=runner,
        timeout=30,
        analysis_seconds=20,
        max_cpu=1,
    )
    argv, workspace, env = calls[0]
    assert argv[0] == str(bwrap.resolve())
    assert "--unshare-all" in argv
    assert "--share-net" not in argv
    ro = argv.index("--ro-bind")
    assert argv[ro + 1 : ro + 3] == ["/", "/"]
    bind = argv.index("--bind")
    assert argv[bind + 1] == str(workspace)
    assert argv[bind + 2] == str(workspace)
    separator = argv.index("--")
    ghidra_argv = argv[separator + 1 :]
    assert ghidra_argv[0] == str(launcher.resolve())
    assert "-import" in ghidra_argv
    assert ghidra_argv[ghidra_argv.index("-import") + 1] == str(artifact.resolve())
    assert "-readOnly" in ghidra_argv
    assert "-deleteProject" in ghidra_argv
    assert ghidra_argv[ghidra_argv.index("-analysisTimeoutPerFile") + 1] == "20"
    assert ghidra_argv[ghidra_argv.index("-max-cpu") + 1] == "1"
    assert result.ok is True
    assert result.provenance["version"].startswith("Ghidra 12.0.4")
    assert result.provenance["sandbox"]["network_shared"] is False
    assert result.provenance["sandbox"]["host_root"] == "read_only"
    assert result.analysis_log_sha256
    assert env.get("GITHUB_TOKEN") is None


def test_ghidra_refuses_unversioned_install_before_sandbox_runner(tmp_path):
    launcher, bwrap = _install(tmp_path, metadata=False)
    artifact = tmp_path / "sample.bin"
    artifact.write_bytes(b"authorized")
    calls = []
    with pytest.raises(GhidraSandboxError, match="install metadata"):
        execute_ghidra_sandboxed(
            artifact_path=artifact,
            ticket=_ticket(),
            runtime_manager=_manager(launcher, bwrap),
            pins={},
            runner=lambda *args: calls.append(args) or GhidraSandboxProcessResult(0),
        )
    assert calls == []


def test_ghidra_refuses_missing_bubblewrap_before_analysis(tmp_path):
    launcher, _bwrap = _install(tmp_path)
    artifact = tmp_path / "sample.bin"
    artifact.write_bytes(b"authorized")

    def resolve(name):
        return str(launcher) if name == "analyzeHeadless" else None

    manager = ToolRuntimeManager(resolver=resolve)
    with pytest.raises(GhidraSandboxError, match="Bubblewrap runtime is unavailable"):
        execute_ghidra_sandboxed(
            artifact_path=artifact,
            ticket=_ticket(),
            runtime_manager=manager,
            pins={},
            runner=lambda *args: GhidraSandboxProcessResult(0),
        )


def test_ghidra_ticket_must_explicitly_include_sandbox_requirement(tmp_path):
    launcher, bwrap = _install(tmp_path)
    artifact = tmp_path / "sample.bin"
    artifact.write_bytes(b"authorized")
    good = _ticket()
    bad = good.__class__(
        ticket_id=good.ticket_id,
        scope_digest=good.scope_digest,
        asset_kind=good.asset_kind,
        tool=good.tool,
        method=good.method,
        requirements=("authorized_artifact",),
        availability_digest=good.availability_digest,
        offline_only=True,
    )
    with pytest.raises(GhidraSandboxError, match="isolated_sandbox"):
        execute_ghidra_sandboxed(
            artifact_path=artifact,
            ticket=bad,
            runtime_manager=_manager(launcher, bwrap),
            pins={},
            runner=lambda *args: GhidraSandboxProcessResult(0),
        )
