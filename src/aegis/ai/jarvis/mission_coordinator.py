"""Adapter from canonical missions to the existing durable scan coordinator."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from aegis.scheduler.coordinator import ScanCoordinator, StageSpec, TaskSpec

from .mission_scheduler import MissionPlan, TaskState


class MissionBackendUnavailable(RuntimeError):
    pass


def materialize_mission(
    plan: MissionPlan,
    coordinator: ScanCoordinator,
    *,
    adapters: Mapping[str, str],
) -> str:
    """Persist a mission in the lease/heartbeat/recovery runtime.

    ``adapters`` maps exact executor capabilities to already registered coordinator adapter
    names. Tasks in an explicit waiting/unavailable state are never silently queued.
    """
    stages: list[StageSpec] = []
    tasks: list[TaskSpec] = []
    task_ids = {task.task_id for task in plan.tasks}
    for task in plan.tasks:
        if task.state in {
            TaskState.WAITING_FOR_PREREQUISITE,
            TaskState.WAITING_FOR_APPROVAL,
            TaskState.UNAVAILABLE,
            TaskState.BLOCKED,
        }:
            raise MissionBackendUnavailable(
                f"task {task.task_id} is {task.state.value}; it cannot be materialized"
            )
        adapter = adapters.get(task.executor_capability)
        if not adapter:
            raise MissionBackendUnavailable(
                f"no durable adapter is registered for {task.executor_capability or task.task_id}"
            )
        unknown = set(task.dependencies) - task_ids
        if unknown:
            raise ValueError(f"task {task.task_id} has unknown dependencies: {sorted(unknown)}")
        stages.append(StageSpec(
            key=task.task_id,
            stage_type=task.action,
            depends_on=task.dependencies,
        ))
        tasks.append(TaskSpec(
            adapter=adapter,
            target=task.asset_locator,
            stage=task.task_id,
            input_hash=task.idempotency_key,
            est_spend=task.expected_cost_usd,
        ))
    return coordinator.plan_scan(stages, tasks)


@dataclass
class DurableMissionTick:
    recovered: tuple[tuple[str, str], ...]
    results: tuple[object, ...]


def durable_tick(
    coordinator: ScanCoordinator,
    scan_ids: tuple[str, ...],
    *,
    worker_id: str = "jarvis-worker",
) -> DurableMissionTick:
    """One restart-safe 24/7 worker tick over existing leases and recovery."""
    recovered = tuple(coordinator.recover())
    results = tuple(
        result
        for scan_id in scan_ids
        if (result := coordinator.run_next(scan_id, worker_id=worker_id)) is not None
    )
    return DurableMissionTick(recovered, results)


__all__ = [
    "DurableMissionTick",
    "MissionBackendUnavailable",
    "durable_tick",
    "materialize_mission",
]
