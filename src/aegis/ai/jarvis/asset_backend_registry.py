"""Concrete execution-backend registry for heterogeneous asset methods.

Capability planning answers whether prerequisites are semantically satisfied. This registry answers
a different question: does Aegis currently have a concrete backend that materially enforces those
prerequisites? It prevents command templates from being mistaken for executable production support.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .android_static import ANDROID_STATIC_METHODS
from .asset_capability_extensions import capability_extensions
from .asset_capability_planner import (
    RuntimeRequirement,
    method_capability_requirements,
    plan_capability_scan,
)
from .asset_deep_capabilities import PlannedMethod, TargetAssetKind
from .firmware_methods import SAFE_ROOTFS_EXTRACT


class BackendKind(str, Enum):
    INTERNAL_ADAPTER = "internal_adapter"
    NETWORKLESS_CLI = "networkless_cli"
    GHIDRA_SANDBOX = "ghidra_bubblewrap_sandbox"
    ANDROID_STATIC = "android_static_networkless"
    FIRMWARE_STATIC = "firmware_static"
    FIRMWARE_EXTRACTION = "firmware_bounded_extraction"
    DYNAMIC_POLICY = "dynamic_policy_required"
    UNIMPLEMENTED = "unimplemented"


@dataclass(frozen=True)
class BackendSupport:
    tool: str
    method: str
    backend: BackendKind
    executable_offline: bool
    reason: str
    semantic_requirements: tuple[str, ...]


@dataclass(frozen=True)
class BackendInventory:
    asset_kind: TargetAssetKind
    supported_ready: tuple[BackendSupport, ...]
    unimplemented_ready: tuple[BackendSupport, ...]
    semantic_blocked: tuple[BackendSupport, ...]


_EXACT = {
    ("MobSF", "rest-static-analysis"): (
        BackendKind.INTERNAL_ADAPTER,
        True,
        "loopback-only MobSF REST adapter",
    ),
    ("aegis-firmware-arch", "firmware-architecture-detection"): (
        BackendKind.FIRMWARE_STATIC,
        True,
        "bytes-only deterministic firmware parser",
    ),
    ("Ghidra", "headless-binary-analysis"): (
        BackendKind.GHIDRA_SANDBOX,
        True,
        "Ghidra launcher + install metadata + Bubblewrap isolation",
    ),
    (SAFE_ROOTFS_EXTRACT.tool, SAFE_ROOTFS_EXTRACT.method): (
        BackendKind.FIRMWARE_EXTRACTION,
        True,
        "bounded ZIP/plain-TAR extraction without links/devices/execution",
    ),
}
for _method in ANDROID_STATIC_METHODS:
    _EXACT[(str(_method.tool), str(_method.method))] = (
        BackendKind.ANDROID_STATIC,
        True,
        "APK-digest-bound JADX/apktool inside Bubblewrap network namespace",
    )

_SPECIAL_RUNTIME = {
    RuntimeRequirement.MOBILE_RUNTIME.value,
    RuntimeRequirement.SANDBOX.value,
    RuntimeRequirement.CLUSTER_ACCESS.value,
    RuntimeRequirement.REGISTRY_ACCESS.value,
    RuntimeRequirement.AUTH_SESSION.value,
}


def backend_for_method(method: PlannedMethod) -> BackendSupport:
    identity = (str(method.tool), str(method.method))
    requirements = tuple(item.value for item in method_capability_requirements(method))
    exact = _EXACT.get(identity)
    if exact is not None:
        backend, executable, reason = exact
        return BackendSupport(identity[0], identity[1], backend, executable, reason, requirements)

    if bool(getattr(method, "requires_network", False)) or bool(
        getattr(method, "state_change_possible", False)
    ):
        return BackendSupport(
            identity[0],
            identity[1],
            BackendKind.DYNAMIC_POLICY,
            False,
            "target-network/state execution requires separate policy-controlled dynamic backend",
            requirements,
        )

    special = set(requirements).intersection(_SPECIAL_RUNTIME)
    if special:
        return BackendSupport(
            identity[0],
            identity[1],
            BackendKind.UNIMPLEMENTED,
            False,
            "semantic runtime has no concrete backend: " + ", ".join(sorted(special)),
            requirements,
        )

    template = tuple(getattr(method, "command_template", ()) or ())
    if bool(getattr(method, "local_only", False)) and template and template[0]:
        return BackendSupport(
            identity[0],
            identity[1],
            BackendKind.NETWORKLESS_CLI,
            True,
            "trusted installed scanner can run through ticketed Bubblewrap networkless backend",
            requirements,
        )

    return BackendSupport(
        identity[0],
        identity[1],
        BackendKind.UNIMPLEMENTED,
        False,
        "no concrete execution adapter is registered",
        requirements,
    )


def inventory_backends(
    asset_kind: TargetAssetKind,
    **planner_kwargs,
) -> BackendInventory:
    """Overlay backend reality on the authoritative semantic plan plus narrow extensions."""
    plan = plan_capability_scan(asset_kind, **planner_kwargs)
    ready_methods: list[PlannedMethod] = list(plan.ready)
    blocked_methods: list[PlannedMethod] = list(plan.blocked)

    firmware_available = bool(planner_kwargs.get("firmware_available", False))
    for extension in capability_extensions(
        asset_kind,
        firmware_available=firmware_available,
    ):
        (ready_methods if extension.ready else blocked_methods).append(extension.method)

    ready_support = tuple(backend_for_method(method) for method in ready_methods)
    blocked_support = tuple(backend_for_method(method) for method in blocked_methods)
    return BackendInventory(
        asset_kind=asset_kind,
        supported_ready=tuple(item for item in ready_support if item.executable_offline),
        unimplemented_ready=tuple(item for item in ready_support if not item.executable_offline),
        semantic_blocked=blocked_support,
    )
