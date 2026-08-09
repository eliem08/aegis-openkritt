"""Resumable mission planning and checkpointing for the Jarvis agent council."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from enum import Enum
from typing import Any, Iterable

from .state_store import JarvisStateStore, MissionSnapshot


class TaskState(str, Enum):
    QUEUED = "queued"
    LEASED = "leased"
    PENDING = "pending"
    RUNNING = "running"
    BLOCKED = "blocked"
    WAITING_FOR_PREREQUISITE = "waiting_for_prerequisite"
    WAITING_FOR_APPROVAL = "waiting_for_approval"
    UNAVAILABLE = "unavailable"
    COMPLETE = "complete"
    COMPLETED = "completed"
    FAILED = "failed"
    FAILED_RETRYABLE = "failed_retryable"
    FAILED_TERMINAL = "failed_terminal"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class MissionTask:
    task_id: str
    agent_role: str
    action: str
    dependencies: tuple[str, ...] = ()
    state: TaskState = TaskState.PENDING
    payload: dict[str, Any] | None = None
    opportunity_id: str = ""
    asset_id: str = ""
    asset_kind: str = "unresolved"
    asset_locator: str = ""
    executor_capability: str = ""
    risk: str = "offline"
    prerequisites: tuple[str, ...] = ()
    expected_requests: int = 0
    expected_cost_usd: float = 0.0
    evidence_required: tuple[str, ...] = ()
    success_criteria: tuple[str, ...] = ()
    failure_criteria: tuple[str, ...] = ()
    stop_loss_criteria: tuple[str, ...] = ()
    idempotency_key: str = ""
    retry_count: int = 0
    max_retries: int = 2


@dataclass(frozen=True)
class MissionPlan:
    mission_id: str
    scope_digest: str
    objective: str
    tasks: tuple[MissionTask, ...]
    state: str = "active"
    cursor: int = 0
    opportunity_id: str = ""
    program_id: str = ""
    asset_id: str = ""
    asset_kind: str = "unresolved"
    authorization_id: str = ""
    expected_net_value_usd: float = 0.0


class MissionScheduler:
    """Dependency-aware scheduler with durable checkpoints and safe resumption."""

    def __init__(self, store: JarvisStateStore) -> None:
        self.store = store

    @staticmethod
    def _serialize(plan: MissionPlan) -> dict[str, Any]:
        return {
            "opportunity_id": plan.opportunity_id,
            "program_id": plan.program_id,
            "asset_id": plan.asset_id,
            "asset_kind": plan.asset_kind,
            "authorization_id": plan.authorization_id,
            "expected_net_value_usd": plan.expected_net_value_usd,
            "tasks": [
                {
                    **asdict(task),
                    "state": task.state.value,
                    "dependencies": list(task.dependencies),
                }
                for task in plan.tasks
            ]
        }

    @staticmethod
    def _deserialize(snapshot: MissionSnapshot) -> MissionPlan:
        tasks = tuple(
            MissionTask(
                task_id=item["task_id"],
                agent_role=item["agent_role"],
                action=item["action"],
                dependencies=tuple(item.get("dependencies", ())),
                state=TaskState(item.get("state", TaskState.PENDING.value)),
                payload=item.get("payload"),
                opportunity_id=str(item.get("opportunity_id", "")),
                asset_id=str(item.get("asset_id", "")),
                asset_kind=str(item.get("asset_kind", "unresolved")),
                asset_locator=str(item.get("asset_locator", "")),
                executor_capability=str(item.get("executor_capability", "")),
                risk=str(item.get("risk", "offline")),
                prerequisites=tuple(item.get("prerequisites", ())),
                expected_requests=int(item.get("expected_requests", 0)),
                expected_cost_usd=float(item.get("expected_cost_usd", 0.0)),
                evidence_required=tuple(item.get("evidence_required", ())),
                success_criteria=tuple(item.get("success_criteria", ())),
                failure_criteria=tuple(item.get("failure_criteria", ())),
                stop_loss_criteria=tuple(item.get("stop_loss_criteria", ())),
                idempotency_key=str(item.get("idempotency_key", "")),
                retry_count=int(item.get("retry_count", 0)),
                max_retries=int(item.get("max_retries", 2)),
            )
            for item in snapshot.payload.get("tasks", [])
        )
        return MissionPlan(
            mission_id=snapshot.mission_id,
            scope_digest=snapshot.scope_digest,
            objective=snapshot.objective,
            tasks=tasks,
            state=snapshot.state,
            cursor=snapshot.cursor,
            opportunity_id=str(snapshot.payload.get("opportunity_id", "")),
            program_id=str(snapshot.payload.get("program_id", "")),
            asset_id=str(snapshot.payload.get("asset_id", "")),
            asset_kind=str(snapshot.payload.get("asset_kind", "unresolved")),
            authorization_id=str(snapshot.payload.get("authorization_id", "")),
            expected_net_value_usd=float(snapshot.payload.get("expected_net_value_usd", 0.0)),
        )

    def create(self, plan: MissionPlan) -> MissionPlan:
        ids = [task.task_id for task in plan.tasks]
        if len(ids) != len(set(ids)):
            raise ValueError("mission task ids must be unique")
        known = set(ids)
        for task in plan.tasks:
            unknown = set(task.dependencies) - known
            if unknown:
                raise ValueError(f"unknown dependencies for {task.task_id}: {sorted(unknown)}")
            if task.task_id in task.dependencies:
                raise ValueError("a mission task cannot depend on itself")
            if plan.opportunity_id and task.opportunity_id not in ("", plan.opportunity_id):
                raise ValueError("mission task references a different opportunity")
            if task.expected_requests < 0 or task.expected_cost_usd < 0:
                raise ValueError("mission task request and cost estimates cannot be negative")
            if task.retry_count < 0 or task.max_retries < 0:
                raise ValueError("mission task retry counts cannot be negative")
        self.checkpoint(plan)
        return plan

    def checkpoint(self, plan: MissionPlan) -> None:
        self.store.save_mission(
            MissionSnapshot(
                mission_id=plan.mission_id,
                scope_digest=plan.scope_digest,
                objective=plan.objective,
                state=plan.state,
                payload=self._serialize(plan),
                cursor=plan.cursor,
            )
        )

    def resume(self, mission_id: str) -> MissionPlan | None:
        snapshot = self.store.load_mission(mission_id)
        return self._deserialize(snapshot) if snapshot is not None else None

    @staticmethod
    def ready_tasks(plan: MissionPlan) -> tuple[MissionTask, ...]:
        states = {task.task_id: task.state for task in plan.tasks}
        ready = []
        for task in plan.tasks:
            if task.state not in (TaskState.PENDING, TaskState.QUEUED, TaskState.FAILED_RETRYABLE):
                continue
            if all(states.get(dep) in (TaskState.COMPLETE, TaskState.COMPLETED)
                   for dep in task.dependencies):
                ready.append(task)
        return tuple(sorted(ready, key=lambda task: task.task_id))

    def set_task_state(
        self,
        plan: MissionPlan,
        task_id: str,
        state: TaskState,
    ) -> MissionPlan:
        found = False
        updated: list[MissionTask] = []
        for task in plan.tasks:
            if task.task_id != task_id:
                updated.append(task)
                continue
            found = True
            if task.state in (TaskState.COMPLETE, TaskState.COMPLETED) and state not in (
                TaskState.COMPLETE, TaskState.COMPLETED,
            ):
                raise ValueError("completed tasks cannot be reopened implicitly")
            retries = task.retry_count + (state is TaskState.FAILED_RETRYABLE)
            if state is TaskState.FAILED_RETRYABLE and retries > task.max_retries:
                state = TaskState.FAILED_TERMINAL
            updated.append(replace(task, state=state, retry_count=retries))
        if not found:
            raise KeyError(task_id)
        terminal = {
            TaskState.COMPLETE, TaskState.COMPLETED, TaskState.CANCELLED,
            TaskState.FAILED_TERMINAL, TaskState.UNAVAILABLE,
        }
        mission_state = (
            "complete" if updated and all(task.state in terminal for task in updated) else plan.state
        )
        next_cursor = sum(task.state in (TaskState.COMPLETE, TaskState.COMPLETED)
                          for task in updated)
        next_plan = replace(plan, tasks=tuple(updated), state=mission_state, cursor=next_cursor)
        self.checkpoint(next_plan)
        return next_plan

    def resumable(self) -> tuple[MissionPlan, ...]:
        snapshots = self.store.list_missions(("active", "blocked"))
        return tuple(self._deserialize(snapshot) for snapshot in snapshots)


def build_linear_mission(
    *,
    mission_id: str,
    scope_digest: str,
    objective: str,
    steps: Iterable[tuple[str, str, str]],
) -> MissionPlan:
    """Build a deterministic dependency chain from (task_id, role, action) steps."""
    tasks: list[MissionTask] = []
    previous: str | None = None
    for task_id, role, action in steps:
        dependencies = (previous,) if previous is not None else ()
        tasks.append(MissionTask(task_id, role, action, dependencies))
        previous = task_id
    return MissionPlan(mission_id, scope_digest, objective, tuple(tasks))
