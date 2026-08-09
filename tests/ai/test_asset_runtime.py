from __future__ import annotations

from aegis.ai.jarvis.asset_capabilities import MOBSF, AssetKind
from aegis.ai.jarvis.asset_capability_planner import CapabilityScanPlan
from aegis.ai.jarvis.asset_deep_capabilities import GHIDRA, DeepScannerMethod
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


def test_mobsf_is_a_concrete_internal_adapter_not_runtime_unknown():
    plan = CapabilityScanPlan(AssetKind.ANDROID_APK, ready=(MOBSF,), blocked=())
    overlay = overlay_runtime(plan, pins={})
    assert overlay.runtime_unknown == ()
    assert len(overlay.internal_adapters) == 1
    assert overlay.internal_adapters[0].method.tool == "MobSF"
    assert "MobSF REST static adapter" in overlay.internal_adapters[0].reason


def test_ghidra_runtime_requires_versioned_launcher_and_bubblewrap(tmp_path):
    root = tmp_path / "ghidra"
    launcher = root / "support" / "analyzeHeadless"
    launcher.parent.mkdir(parents=True)
    launcher.write_bytes(b"#!/bin/sh\n")
    properties = root / "Ghidra" / "application.properties"
    properties.parent.mkdir(parents=True)
    properties.write_text("application.version=12.0.4\n", encoding="utf-8")
    bwrap = tmp_path / "bwrap"
    bwrap.write_bytes(b"bubblewrap")

    def resolver(name):
        return {
            "analyzeHeadless": str(launcher),
            "bwrap": str(bwrap),
        }.get(name)

    def runner(argv, timeout):
        if argv[0] == str(bwrap):
            return 0, "bubblewrap 0.11.0", ""
        raise AssertionError("Ghidra must use install metadata instead of version execution")

    manager = ToolRuntimeManager(resolver=resolver, runner=runner)
    plan = CapabilityScanPlan(AssetKind.EXECUTABLE, ready=(GHIDRA,), blocked=())
    overlay = overlay_runtime(plan, manager=manager, pins={})
    assert len(overlay.runtime_ready) == 1
    item = overlay.runtime_ready[0]
    assert item.method.tool == "Ghidra"
    assert item.runtime["ghidra"]["version"].startswith("Ghidra 12.0.4")
    assert item.runtime["bubblewrap"]["status"] == "ready"

    missing_bwrap = ToolRuntimeManager(
        resolver=lambda name: str(launcher) if name == "analyzeHeadless" else None
    )
    overlay = overlay_runtime(plan, manager=missing_bwrap, pins={})
    assert overlay.runtime_ready == ()
    assert overlay.runtime_blocked[0].runtime["bubblewrap"]["status"] == "unavailable"


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
