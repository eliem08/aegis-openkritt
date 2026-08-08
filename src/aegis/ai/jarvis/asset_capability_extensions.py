"""Narrow capability extensions layered on the authoritative base planner.

This module exists to avoid duplicating ``plan_capability_scan`` while newer safe internal
methods are introduced. Both the planning agent and execution-ticket issuer consume this exact
hook, so a method cannot be proposed through one path and authorized through another.

Extensions are intentionally tiny and deterministic; long-term they can be folded into the base
registry without changing callers.
"""

from __future__ import annotations

from dataclasses import dataclass

from .asset_capabilities import AssetKind, Requirement
from .asset_deep_capabilities import PlannedMethod, TargetAssetKind
from .firmware_methods import SAFE_ROOTFS_EXTRACT


@dataclass(frozen=True)
class CapabilityExtension:
    method: PlannedMethod
    ready: bool
    missing_requirements: tuple[Requirement, ...] = ()


def capability_extensions(
    asset_kind: TargetAssetKind,
    *,
    firmware_available: bool = False,
) -> tuple[CapabilityExtension, ...]:
    """Return safe methods not yet present in the base registry with explicit readiness."""
    if asset_kind is not AssetKind.HARDWARE:
        return ()
    return (
        CapabilityExtension(
            method=SAFE_ROOTFS_EXTRACT,
            ready=bool(firmware_available),
            missing_requirements=() if firmware_available else (Requirement.FIRMWARE,),
        ),
    )


def extension_method(
    asset_kind: TargetAssetKind,
    tool: str,
    method: str,
    *,
    firmware_available: bool = False,
) -> CapabilityExtension | None:
    identity = (str(tool), str(method))
    for item in capability_extensions(asset_kind, firmware_available=firmware_available):
        if (str(item.method.tool), str(item.method.method)) == identity:
            return item
    return None
