"""Resumable mission planning and checkpointing for the Jarvis agent council."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Iterable

from .state_store import JarvisStateStore, MissionSnapshot


class TaskState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    BLOCKED = "blocked"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class MissionTask:
    task_id: str
    agent_role: str
    action: str
    dependencies: tuple[str, ...] = ()
    state: TaskState = TaskState.PENDING
    payload: dict[str, Any] | None = None


@dataclass(frozen=True)
class MissionPlan:
    mission_id: str
    scope_digest: str
    objective: str
    tasks: tuple[MissionTask, ...]
    state: str = "active"
    cursor: int = 0


class MissionScheduler:
    """Dependency-aware scheduler with durable checkpoints and safe resumption."""

    def __init__(self, store: JarvisStateStore) -> None:
        self.store = store

    @staticmethod
    def _serialize(plan: MissionPlan) -> dict[str, Any]:
        return {
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
            if task.state is not TaskState.PENDING:
                continue
            if all(states.get(dep) is TaskState.COMPLETE for dep in task.dependencies):
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
            if task.state is TaskState.COMPLETE and state is not TaskState.COMPLETE:
                raise ValueError("completed tasks cannot be reopened implicitly")
            updated.append(
                MissionTask(
                    task_id=task.task_id,
                    agent_role=task.agent_role,
                    action=task.action,
                    dependencies=task.dependencies,
                    state=state,
                    payload=task.payload,
                )
            )
        if not found:
            raise KeyError(task_id)
        terminal = {TaskState.COMPLETE, TaskState.CANCELLED}
        mission_state = (
            "complete" if updated and all(task.state in terminal for task in updated) else plan.state
        )
        next_cursor = sum(task.state is TaskState.COMPLETE for task in updated)
        next_plan = MissionPlan(
            mission_id=plan.mission_id,
            scope_digest=plan.scope_digest,
            objective=plan.objective,
            tasks=tuple(updated),
            state=mission_state,
            cursor=next_cursor,
        )
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
