from __future__ import annotations

from pathlib import Path

import pytest

from aegis.ai.jarvis.asset_cli_executor import CliProcessResult
from aegis.ai.jarvis.asset_capabilities import SLITHER
from aegis.ai.jarvis.asset_deep_capabilities import MYTHRIL
from aegis.ai.jarvis.contract_static_pipeline import ContractStaticError, run_contract_static_pipeline
from aegis.ai.tool_runtime import ToolRuntimeManager


def _source(tmp_path):
    source = tmp_path / "Vault.sol"
    source.write_text(
        "pragma solidity ^0.8.20; contract Vault { function ping() external pure returns(uint){return 1;} }",
        encoding="utf-8",
    )
    return source


def _manager(tmp_path, tools=("slither", "myth"), *, bwrap=True):
    binaries = {}
    for name in tools:
        path = tmp_path / name
        path.write_bytes(name.encode())
        binaries[name] = path
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


def test_default_pipeline_uses_only_slither_and_mythril_inside_networkless_namespace(tmp_path):
    source = _source(tmp_path)
    manager, binaries = _manager(tmp_path)
    calls = []

    def process_runner(argv, workspace, timeout, env, maximum_output_bytes):
        calls.append(argv)
        scanner = argv[argv.index("--") + 1 :]
        assert str(source.resolve()) in scanner
        return CliProcessResult(0, b"{}", b"")

    report = run_contract_static_pipeline(
        source,
        scope_digest="scope:contract",
        workspace_root=tmp_path / "work",
        runtime_manager=manager,
        pins={},
        process_runner=process_runner,
    )
    statuses = {stage.stage: stage.status for stage in report.stages}
    assert set(statuses) == {
        f"{SLITHER.tool}/{SLITHER.method}",
        f"{MYTHRIL.tool}/{MYTHRIL.method}",
    }
    assert set(statuses.values()) == {"complete"}
    assert report.engine_errors == {}
    assert len(report.source_sha256) == 64
    assert all(argv[0] == str(binaries["bwrap"].resolve()) for argv in calls)
    assert all("--unshare-all" in argv and "--share-net" not in argv for argv in calls)
    assert not any("forge" in " ".join(argv).lower() for argv in calls)
    assert not any("echidna" in " ".join(argv).lower() for argv in calls)


def test_missing_bubblewrap_preserves_engine_failures_without_host_fallback(tmp_path):
    source = _source(tmp_path)
    manager, _binaries = _manager(tmp_path, bwrap=False)
    report = run_contract_static_pipeline(
        source,
        scope_digest="scope:contract",
        methods=(SLITHER,),
        runtime_manager=manager,
        pins={},
    )
    assert report.stages[0].status == "failed"
    assert f"{SLITHER.tool}/{SLITHER.method}" in report.engine_errors
    assert report.candidates == []


def test_source_mutation_during_scanner_run_is_detected(tmp_path):
    source = _source(tmp_path)
    manager, _binaries = _manager(tmp_path, tools=("slither",))

    def process_runner(argv, workspace, timeout, env, maximum_output_bytes):
        source.write_text(source.read_text(encoding="utf-8") + "\n// tampered", encoding="utf-8")
        return CliProcessResult(0, b"{}", b"")

    report = run_contract_static_pipeline(
        source,
        scope_digest="scope:contract",
        methods=(SLITHER,),
        runtime_manager=manager,
        pins={},
        process_runner=process_runner,
    )
    assert report.stages[0].status == "failed"
    assert "changed after scanner execution" in report.engine_errors[report.stages[0].stage]


def test_non_solidity_and_missing_sources_fail_before_tool_execution(tmp_path):
    wrong = tmp_path / "Vault.txt"
    wrong.write_text("contract Vault {}", encoding="utf-8")
    with pytest.raises(ContractStaticError, match=".sol"):
        run_contract_static_pipeline(wrong, scope_digest="scope:contract")
    with pytest.raises(ContractStaticError, match="existing regular file"):
        run_contract_static_pipeline(tmp_path / "missing.sol", scope_digest="scope:contract")
