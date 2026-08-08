from __future__ import annotations

import json
import struct
from pathlib import Path

from aegis.ai.jarvis.asset_cli_executor import CliProcessResult
from aegis.ai.jarvis.asset_capabilities import CAPA, GRYPE, SYFT
from aegis.ai.jarvis.binary_pipeline import run_binary_offline_pipeline
from aegis.ai.tool_runtime import ToolRuntimeManager


def _pe64(*, dll_characteristics: int) -> bytes:
    data = bytearray(0x300)
    data[:2] = b"MZ"
    pe = 0x80
    struct.pack_into("<I", data, 0x3C, pe)
    data[pe:pe + 4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, pe + 4, 0x8664, 3, 0, 0, 0, 0xF0, 0x0002)
    optional = pe + 24
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<H", data, optional + 70, dll_characteristics)
    return bytes(data)


def _manager(tmp_path, tools=("capa", "syft", "grype"), *, include_bwrap=True):
    binaries = {}
    for name in tools:
        path = tmp_path / name
        path.write_bytes(name.encode())
        binaries[name] = path
    bwrap = tmp_path / "bwrap"
    if include_bwrap:
        bwrap.write_bytes(b"bwrap")
        binaries["bwrap"] = bwrap

    def resolver(name):
        path = binaries.get(name)
        return str(path) if path is not None else None

    def version(argv, timeout):
        name = Path(argv[0]).name
        if name in binaries:
            return 0, f"{name} 1.0", ""
        return 1, "", ""

    return ToolRuntimeManager(resolver=resolver, runner=version), binaries


def test_pipeline_combines_header_hypotheses_grype_and_inventory_observations(tmp_path):
    binary = tmp_path / "legacy.exe"
    binary.write_bytes(_pe64(dll_characteristics=0))
    manager, binaries = _manager(tmp_path)
    calls = []

    grype_payload = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2099-3000",
                    "severity": "High",
                    "description": "demo dependency vulnerability",
                },
                "artifact": {
                    "name": "demo",
                    "version": "1",
                    "locations": [{"path": "legacy.exe"}],
                },
            }
        ]
    }
    syft_payload = {"artifacts": [{"name": "demo"}], "source": {"type": "file"}}

    def process_runner(argv, workspace, timeout, env, maximum_output_bytes):
        calls.append(argv)
        scanner = argv[argv.index("--") + 1 :]
        name = Path(scanner[0]).name
        if name == "grype":
            return CliProcessResult(0, json.dumps(grype_payload).encode(), b"")
        if name == "syft":
            return CliProcessResult(0, json.dumps(syft_payload).encode(), b"")
        if name == "capa":
            return CliProcessResult(0, json.dumps({"rules": {"capability": {}}}).encode(), b"")
        raise AssertionError(name)

    report = run_binary_offline_pipeline(
        binary,
        scope_digest="scope:binary",
        scanner_methods=(CAPA, SYFT, GRYPE),
        workspace_root=tmp_path / "work",
        runtime_manager=manager,
        pins={},
        process_runner=process_runner,
    )
    statuses = {stage.stage: stage.status for stage in report.stages}
    assert statuses["metadata"] == "complete"
    assert statuses[f"{CAPA.tool}/{CAPA.method}"] == "complete"
    assert statuses[f"{SYFT.tool}/{SYFT.method}"] == "complete"
    assert statuses[f"{GRYPE.tool}/{GRYPE.method}"] == "complete"
    assert report.engine_errors == {}

    kinds = {row.get("scanner_metadata", {}).get("analysis_kind") for row in report.candidates}
    assert {"pe_nx_missing", "pe_aslr_missing"} <= kinds
    assert any(row["source"] == "aegis:tool:grype" for row in report.candidates)
    assert all(row["validation_status"] == "unverified" for row in report.candidates)

    observation_kinds = {item.kind for item in report.observations}
    assert "binary_metadata" in observation_kinds
    assert "sbom_inventory" in observation_kinds
    assert "tool_observation" in observation_kinds  # capa has no dedicated vuln parser here
    assert all("--unshare-all" in argv and "--share-net" not in argv for argv in calls)
    assert all(argv[0] == str(binaries["bwrap"].resolve()) for argv in calls)


def test_pipeline_records_missing_bubblewrap_as_scanner_failures_but_keeps_metadata(tmp_path):
    binary = tmp_path / "safe.exe"
    binary.write_bytes(_pe64(dll_characteristics=0x0040 | 0x0100))
    manager, _binaries = _manager(tmp_path, tools=("grype",), include_bwrap=False)
    report = run_binary_offline_pipeline(
        binary,
        scope_digest="scope:binary",
        scanner_methods=(GRYPE,),
        runtime_manager=manager,
        pins={},
    )
    statuses = {stage.stage: stage.status for stage in report.stages}
    assert statuses["metadata"] == "complete"
    assert statuses[f"{GRYPE.tool}/{GRYPE.method}"] == "failed"
    assert f"{GRYPE.tool}/{GRYPE.method}" in report.engine_errors
    assert any(item.kind == "binary_metadata" for item in report.observations)


def test_pipeline_does_not_run_ghidra_without_explicit_sandbox_availability(tmp_path):
    binary = tmp_path / "safe.exe"
    binary.write_bytes(_pe64(dll_characteristics=0x0040 | 0x0100))
    report = run_binary_offline_pipeline(
        binary,
        scope_digest="scope:binary",
        scanner_methods=(),
        include_ghidra=True,
        sandbox_available=False,
        runtime_manager=ToolRuntimeManager(resolver=lambda _name: None),
        pins={},
    )
    ghidra_stage = next(stage for stage in report.stages if stage.stage.startswith("Ghidra/"))
    assert ghidra_stage.status == "failed"
    assert "isolated_sandbox" in report.engine_errors[ghidra_stage.stage]
    assert all(item.kind != "binary_analysis" for item in report.observations)


def test_unsupported_binary_stops_before_scanners(tmp_path):
    binary = tmp_path / "blob.bin"
    binary.write_bytes(b"not a pe or elf")
    calls = []
    report = run_binary_offline_pipeline(
        binary,
        scope_digest="scope:binary",
        scanner_methods=(GRYPE,),
        runtime_manager=ToolRuntimeManager(resolver=lambda _name: None),
        pins={},
        process_runner=lambda *args: calls.append(args) or CliProcessResult(0),
    )
    assert report.stages[0].stage == "metadata"
    assert report.stages[0].status == "failed"
    assert calls == []
