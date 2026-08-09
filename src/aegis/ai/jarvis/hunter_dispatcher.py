"""Exact-capability dispatcher for internal, networkless hunter workers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from aegis.ai.agentic_os import AuthorizationEnvelope

from .mission_scheduler import MissionPlan, MissionTask

InternalHunterExecutor = Callable[[MissionTask, MissionPlan, AuthorizationEnvelope], Any]


@dataclass(frozen=True, slots=True)
class HunterDispatchResult:
    capability: str
    result: Any


class HunterCapabilityDispatcher:
    """Dispatch exact registered internal capabilities; prefixes never confer execution."""

    def __init__(self, executors: Mapping[str, InternalHunterExecutor] | None = None) -> None:
        self._executors = dict(executors or {})

    def register(self, capability: str, executor: InternalHunterExecutor) -> None:
        if not capability.startswith("jarvis:") or "*" in capability:
            raise ValueError("internal hunter capability must be an exact jarvis capability")
        self._executors[capability] = executor

    def has(self, capability: str) -> bool:
        return capability in self._executors

    def dispatch(self, task: MissionTask, plan: MissionPlan,
                 authorization: AuthorizationEnvelope) -> HunterDispatchResult:
        if task.risk not in {"offline", "read_only"}:
            raise PermissionError("internal hunter dispatcher cannot execute state-changing work")
        executor = self._executors.get(task.executor_capability)
        if executor is None:
            raise LookupError(f"no internal executor registered for {task.executor_capability}")
        return HunterDispatchResult(task.executor_capability,
                                    executor(task, plan, authorization))

    def runtime_executors(self) -> dict[str, InternalHunterExecutor]:
        return dict(self._executors)


__all__ = ["HunterCapabilityDispatcher", "HunterDispatchResult", "InternalHunterExecutor"]
