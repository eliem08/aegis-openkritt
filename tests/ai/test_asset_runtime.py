from __future__ import annotations

from aegis.ai.jarvis.asset_capabilities import AssetKind
from aegis.ai.jarvis.asset_capability_planner import CapabilityScanPlan
from aegis.ai.jarvis.asset_deep_capabilities import DeepScannerMethod
from aegis.ai.jarvis.asset_runtime import RuntimeDisposition, overlay_runtime
from aegis.ai.tool_runtime import ToolRuntimeManager


def test_runtime_overlay_separates_cli_internal_unknown_and_prerequisite_blocked(tmp_path):
    binary = tmp_path / "scanner"
    binary.write_bytes(b"scanner")
    manager = ToolRuntimeManager(
        resolver=lambda name: str(binary) if name == "scanner" else None,
        runner=lambda argv, timeout: (0, "scanner 1.0", ""),
    )
    cli = DeepScannerMethod("scanner", "cli", ("scanner", "--json"))
    internal = DeepScannerMethod("aegis-local-adapter", "internal")
    unknown = DeepScannerMethod("PythonLibraryOnly", "library")
    missing_prereq = DeepScannerMethod("scanner", "blocked", ("scanner", "--json"))
    plan = CapabilityScanPlan(
        asset_kind=AssetKind.SOURCE_CODE,
        ready=(cli, internal, unknown),
        blocked=(missing_prereq,),
    )

    overlay = overlay_runtime(plan, manager=manager, pins={})
    assert [item.disposition for item in overlay.runtime_ready] == [RuntimeDisposition.READY]
    assert [item.disposition for item in overlay.internal_adapters] == [RuntimeDisposition.INTERNAL]
    assert [item.disposition for item in overlay.runtime_unknown] == [RuntimeDisposition.UNKNOWN]
    assert [item.disposition for item in overlay.prerequisite_blocked] == [
        RuntimeDisposition.PREREQUISITE_BLOCKED
    ]


def test_runtime_overlay_blocks_missing_cli_without_executing_scan_target():
    calls = []
    manager = ToolRuntimeManager(
        resolver=lambda name: None,
        runner=lambda argv, timeout: calls.append(argv) or (0, "scanner 1.0", ""),
    )
    method = DeepScannerMethod("scanner", "cli", ("scanner", "{target}"))
    plan = CapabilityScanPlan(AssetKind.SOURCE_CODE, ready=(method,), blocked=())
    overlay = overlay_runtime(plan, manager=manager, pins={})
    assert overlay.runtime_ready == ()
    assert overlay.runtime_blocked[0].runtime["status"] == "unavailable"
    assert calls == []
