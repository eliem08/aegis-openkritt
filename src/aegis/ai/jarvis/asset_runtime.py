"""Worker-runtime overlay for heterogeneous asset capability plans.

``plan_capability_scan`` answers a semantic question: given authorized artifacts/sessions/etc.,
which methods are logically allowed? This module answers the separate operational question:
is the exact external tool actually healthy on this worker?

It never executes a scan. CLI-backed methods are fingerprinted through ``ToolRuntimeManager``;
concrete Aegis service adapters are identified explicitly, while runtimes without a stable
execution contract remain ``runtime_unknown`` rather than being falsely marked ready.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ..tool_runtime import ToolPin, ToolRuntimeManager, ToolRuntimeStatus, load_tool_pins
from .asset_capability_planner import CapabilityScanPlan
from .asset_deep_capabilities import PlannedMethod


class RuntimeDisposition(str, Enum):
    READY = "runtime_ready"
    BLOCKED = "runtime_blocked"
    INTERNAL = "internal_adapter"
    UNKNOWN = "runtime_unknown"
    PREREQUISITE_BLOCKED = "prerequisite_blocked"


@dataclass(frozen=True)
class AssetMethodRuntime:
    method: PlannedMethod
    disposition: RuntimeDisposition
    binary: str = ""
    runtime: dict | None = None
    reason: str = ""


@dataclass(frozen=True)
class AssetRuntimeOverlay:
    asset_kind: object
    runtime_ready: tuple[AssetMethodRuntime, ...]
    runtime_blocked: tuple[AssetMethodRuntime, ...]
    internal_adapters: tuple[AssetMethodRuntime, ...]
    runtime_unknown: tuple[AssetMethodRuntime, ...]
    prerequisite_blocked: tuple[AssetMethodRuntime, ...]


# Only stable, well-known CLI entry points belong here. A missing mapping is not guessed.
_CLI_OVERRIDES = {
    "RustScan": "rustscan",
    "Frida": "frida",
    "Ghidra": "analyzeHeadless",
    "FLOSS": "floss",
    "YARA": "yara",
    "Rizin": "rizin",
    "Echidna": "echidna",
    "Foundry": "forge",
    "Mythril": "myth",
    "Schemathesis": "schemathesis",
    "Playwright": "playwright",
    "ScoutSuite": "scout",
    "Cloudsplaining": "cloudsplaining",
    "ROADtools": "roadrecon",
    "AzureHound": "azurehound",
    "Kubescape": "kubescape",
    "Trivy": "trivy",
    "Syft": "syft",
    "Grype": "grype",
    "Checkov": "checkov",
    "KICS": "kics",
    "ModelScan": "modelscan",
    "garak": "garak",
    "promptfoo": "promptfoo",
    "web-ext": "web-ext",
    "OSV-Scanner": "osv-scanner",
    "pip-audit": "pip-audit",
}

# Concrete service/library adapters owned by Aegis rather than an external CLI process.
_INTERNAL_ADAPTERS = {
    "MobSF": "loopback MobSF REST static adapter",
}


def method_binary(method: PlannedMethod) -> str:
    """Return a stable CLI entry point, or empty string when no honest mapping exists."""
    template = tuple(getattr(method, "command_template", ()) or ())
    if template and template[0] and not str(template[0]).startswith("{"):
        return str(template[0])
    return _CLI_OVERRIDES.get(str(method.tool), "")


def _pin_for(method: PlannedMethod, binary: str, pins: dict[str, ToolPin]) -> ToolPin | None:
    return pins.get(str(method.tool)) or pins.get(str(method.tool).lower()) or pins.get(binary)


def overlay_runtime(
    plan: CapabilityScanPlan,
    *,
    manager: ToolRuntimeManager | None = None,
    pins: dict[str, ToolPin] | None = None,
) -> AssetRuntimeOverlay:
    runtime = manager or ToolRuntimeManager()
    configured_pins = pins if pins is not None else load_tool_pins()
    ready: list[AssetMethodRuntime] = []
    blocked: list[AssetMethodRuntime] = []
    internal: list[AssetMethodRuntime] = []
    unknown: list[AssetMethodRuntime] = []

    for method in plan.ready:
        tool_name = str(method.tool)
        internal_reason = _INTERNAL_ADAPTERS.get(tool_name)
        if tool_name.startswith("aegis-") or internal_reason:
            internal.append(
                AssetMethodRuntime(
                    method,
                    RuntimeDisposition.INTERNAL,
                    reason=internal_reason or (
                        "Aegis-internal adapter; external binary health is not applicable"
                    ),
                )
            )
            continue
        binary = method_binary(method)
        if not binary:
            unknown.append(
                AssetMethodRuntime(
                    method,
                    RuntimeDisposition.UNKNOWN,
                    reason="no stable CLI/runtime contract is registered for this method",
                )
            )
            continue
        record = runtime.inspect(
            name=tool_name,
            binary=binary,
            pin=_pin_for(method, binary, configured_pins),
        )
        item = AssetMethodRuntime(
            method,
            RuntimeDisposition.READY if record.status is ToolRuntimeStatus.READY
            else RuntimeDisposition.BLOCKED,
            binary=binary,
            runtime=record.as_dict(),
            reason=record.reason,
        )
        (ready if record.status is ToolRuntimeStatus.READY else blocked).append(item)

    prerequisite_blocked = tuple(
        AssetMethodRuntime(
            method,
            RuntimeDisposition.PREREQUISITE_BLOCKED,
            binary=method_binary(method),
            reason="semantic authorization/prerequisite is not satisfied",
        )
        for method in plan.blocked
    )
    return AssetRuntimeOverlay(
        asset_kind=plan.asset_kind,
        runtime_ready=tuple(ready),
        runtime_blocked=tuple(blocked),
        internal_adapters=tuple(internal),
        runtime_unknown=tuple(unknown),
        prerequisite_blocked=prerequisite_blocked,
    )
