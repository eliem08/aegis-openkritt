from __future__ import annotations

import pytest

from aegis.ai.jarvis.mission_coordinator import (
    MissionBackendUnavailable,
    durable_tick,
    materialize_mission,
)
from aegis.ai.jarvis.mission_scheduler import MissionPlan, MissionTask, TaskState


class _Coordinator:
    def __init__(self):
        self.planned = None
        self.calls = []

    def plan_scan(self, stages, tasks):
        self.planned = (stages, tasks)
        return "scan:durable"

    def recover(self):
        return [("expired", "requeued")]

    def run_next(self, scan_id, worker_id="worker"):
        self.calls.append((scan_id, worker_id))
        return None if scan_id == "idle" else f"ran:{scan_id}"


def _plan(state=TaskState.PENDING):
    first = MissionTask(
        "discover", "research", "discover", state=state,
        executor_capability="tool:discover", asset_locator="asset",
        idempotency_key="mission:discover", expected_cost_usd=0.1,
    )
    second = MissionTask(
        "validate", "research", "validate", dependencies=("discover",),
        executor_capability="tool:validate", asset_locator="asset",
        idempotency_key="mission:validate", expected_cost_usd=0.2,
    )
    return MissionPlan("mission", "scope", "objective", (first, second))


def test_mission_materializes_into_existing_durable_coordinator():
    coordinator = _Coordinator()
    scan_id = materialize_mission(
        _plan(), coordinator,
        adapters={"tool:discover": "discover-adapter", "tool:validate": "validate-adapter"},
    )
    assert scan_id == "scan:durable"
    stages, tasks = coordinator.planned
    assert stages[1].depends_on == ("discover",)
    assert tasks[0].input_hash == "mission:discover"
    assert tasks[1].est_spend == 0.2


def test_waiting_or_unmapped_task_never_enters_durable_queue():
    with pytest.raises(MissionBackendUnavailable, match="waiting_for_prerequisite"):
        materialize_mission(
            _plan(TaskState.WAITING_FOR_PREREQUISITE), _Coordinator(), adapters={}
        )
    with pytest.raises(MissionBackendUnavailable, match="no durable adapter"):
        materialize_mission(_plan(), _Coordinator(), adapters={})


def test_durable_tick_reuses_recovery_and_worker_claims():
    coordinator = _Coordinator()
    tick = durable_tick(coordinator, ("scan", "idle"), worker_id="worker-7")
    assert tick.recovered == (("expired", "requeued"),)
    assert tick.results == ("ran:scan",)
    assert coordinator.calls == [("scan", "worker-7"), ("idle", "worker-7")]
