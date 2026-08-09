"""Capability matching for canonical mission tasks over existing worker registries."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from fnmatch import fnmatchcase

from .asset_backend_registry import BackendKind, inventory_backends
from .asset_capabilities import AssetKind
from .asset_deep_capabilities import ExtendedAssetKind, TargetAssetKind
from .asset_execution_ticket import CapabilityAvailability
from .mission_scheduler import MissionTask


class ExecutionClass(str, Enum):
    REAL_EXECUTOR = "real_executor"
    INTERNAL_EXECUTOR = "internal_executor"
    DYNAMIC_POLICY_EXECUTOR = "dynamic_policy_executor"
    EXTERNAL_SERVICE = "external_service"
    UNAVAILABLE = "unavailable"


class CapabilityDisposition(str, Enum):
    READY = "ready"
    WAITING_FOR_PREREQUISITE = "waiting_for_prerequisite"
    WAITING_FOR_APPROVAL = "waiting_for_approval"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class WorkerCapability:
    capability_pattern: str
    execution_class: ExecutionClass
    asset_kinds: tuple[str, ...] = ("*",)
    risk_classes: tuple[str, ...] = ("offline", "read_only")
    concurrency: int = 1

    def accepts(self, task: MissionTask) -> bool:
        return (
            fnmatchcase(task.executor_capability, self.capability_pattern)
            and any(fnmatchcase(task.asset_kind, item) for item in self.asset_kinds)
            and task.risk in self.risk_classes
        )


@dataclass(frozen=True)
class CapabilityMatch:
    disposition: CapabilityDisposition
    execution_class: ExecutionClass
    capability: str
    reason: str
    tool: str = ""
    method: str = ""


class MissionWorkerRegistry:
    """Match tasks without granting authority or executing them."""

    def __init__(self, capabilities: tuple[WorkerCapability, ...] | None = None) -> None:
        self.capabilities = capabilities or (
            WorkerCapability("jarvis:research:*", ExecutionClass.INTERNAL_EXECUTOR),
            WorkerCapability("jarvis:evidence:*", ExecutionClass.INTERNAL_EXECUTOR),
            WorkerCapability("jarvis:judge:*", ExecutionClass.INTERNAL_EXECUTOR),
            WorkerCapability("jarvis:reproduction:*", ExecutionClass.INTERNAL_EXECUTOR),
        )

    def match(
        self,
        task: MissionTask,
        *,
        availability: CapabilityAvailability | None = None,
    ) -> CapabilityMatch:
        if not task.executor_capability:
            return _unavailable(task, "mission task declares no executor capability")
        if task.risk == "controlled_state_change":
            return CapabilityMatch(
                CapabilityDisposition.WAITING_FOR_APPROVAL,
                ExecutionClass.DYNAMIC_POLICY_EXECUTOR,
                task.executor_capability,
                "state-changing work requires PolicyEngine approval and a signed ExecutionGrant",
            )
        for capability in self.capabilities:
            if capability.accepts(task):
                return CapabilityMatch(
                    CapabilityDisposition.READY,
                    capability.execution_class,
                    task.executor_capability,
                    "registered internal mission worker",
                )
        if ":" not in task.executor_capability:
            return _unavailable(task, "capability must be a registered worker or tool:method")
        tool, method = task.executor_capability.split(":", 1)
        asset_kind = _asset_kind(task.asset_kind)
        if asset_kind is None:
            return _unavailable(task, f"unsupported asset kind: {task.asset_kind}", tool, method)
        inventory = inventory_backends(
            asset_kind,
            **(availability or CapabilityAvailability()).planner_kwargs(),
        )
        identity = (tool.casefold(), method.casefold())
        for support in inventory.supported_ready:
            if _identity(support.tool, support.method) == identity:
                execution_class = (
                    ExecutionClass.INTERNAL_EXECUTOR
                    if support.backend is BackendKind.INTERNAL_ADAPTER
                    else ExecutionClass.REAL_EXECUTOR
                )
                return CapabilityMatch(
                    CapabilityDisposition.READY,
                    execution_class,
                    task.executor_capability,
                    support.reason,
                    support.tool,
                    support.method,
                )
        for support in inventory.semantic_blocked:
            if _identity(support.tool, support.method) == identity:
                return CapabilityMatch(
                    CapabilityDisposition.WAITING_FOR_PREREQUISITE,
                    ExecutionClass.UNAVAILABLE,
                    task.executor_capability,
                    support.reason,
                    support.tool,
                    support.method,
                )
        for support in inventory.unimplemented_ready:
            if _identity(support.tool, support.method) != identity:
                continue
            if support.backend is BackendKind.DYNAMIC_POLICY:
                return CapabilityMatch(
                    CapabilityDisposition.WAITING_FOR_APPROVAL,
                    ExecutionClass.DYNAMIC_POLICY_EXECUTOR,
                    task.executor_capability,
                    support.reason,
                    support.tool,
                    support.method,
                )
            return CapabilityMatch(
                CapabilityDisposition.UNAVAILABLE,
                ExecutionClass.UNAVAILABLE,
                task.executor_capability,
                support.reason,
                support.tool,
                support.method,
            )
        return _unavailable(task, "capability is not registered for this asset kind", tool, method)


def _asset_kind(value: str) -> TargetAssetKind | None:
    try:
        return AssetKind(value)
    except ValueError:
        try:
            return ExtendedAssetKind(value)
        except ValueError:
            return None


def _identity(tool: str, method: str) -> tuple[str, str]:
    return tool.casefold(), method.casefold()


def _unavailable(task: MissionTask, reason: str, tool: str = "", method: str = "") -> CapabilityMatch:
    return CapabilityMatch(
        CapabilityDisposition.UNAVAILABLE,
        ExecutionClass.UNAVAILABLE,
        task.executor_capability,
        reason,
        tool,
        method,
    )


__all__ = [
    "CapabilityDisposition",
    "CapabilityMatch",
    "ExecutionClass",
    "MissionWorkerRegistry",
    "WorkerCapability",
]
