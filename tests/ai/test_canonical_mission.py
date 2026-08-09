from __future__ import annotations

from decimal import Decimal

from aegis.ai.jarvis.asset_execution_ticket import CapabilityAvailability
from aegis.ai.jarvis.mission_capabilities import (
    CapabilityDisposition,
    ExecutionClass,
    MissionWorkerRegistry,
)
from aegis.ai.jarvis.mission_scheduler import MissionScheduler, MissionTask, TaskState
from aegis.ai.jarvis.state_store import JarvisStateStore
from aegis.ai.jarvis.universal_mission import compile_opportunity_mission
from aegis.scheduler.profit import HuntOpportunity


def _opportunity(**changes) -> HuntOpportunity:
    values = dict(
        opportunity_id="opp:source:authz",
        program_id="program:acme",
        program_handle="acme",
        asset_id="asset:repo",
        asset_kind="source_code",
        asset_locator="acme/repo",
        scope_digest="scope123",
        authorization_id="auth123",
        attack_surface="source",
        weakness_family="authz",
        estimated_payout_usd=Decimal("3000"),
        p_find=0.5,
        p_valid=0.7,
        p_unique=0.6,
        p_accepted=0.8,
        validation_cost_usd=Decimal("4"),
    )
    values.update(changes)
    return HuntOpportunity(**values)


def test_opportunity_compiles_to_typed_cross_asset_mission():
    opportunity = _opportunity()
    mission = compile_opportunity_mission(opportunity)
    assert mission.opportunity_id == opportunity.opportunity_id
    assert mission.asset_id == "asset:repo"
    assert mission.authorization_id == "auth123"
    assert mission.expected_net_value_usd > 0
    assert mission.tasks[-1].action == "assemble_evidence_bundle"
    assert all(task.opportunity_id == opportunity.opportunity_id for task in mission.tasks)
    assert all(task.executor_capability and task.evidence_required for task in mission.tasks)
    assert all(task.idempotency_key for task in mission.tasks)


def test_missing_acquisition_state_is_explicit_on_every_task():
    mission = compile_opportunity_mission(
        _opportunity(prerequisite_state="waiting_for_artifact")
    )
    assert {task.state for task in mission.tasks} == {TaskState.WAITING_FOR_PREREQUISITE}
    assert all(task.prerequisites == ("waiting_for_artifact",) for task in mission.tasks)


def test_typed_mission_roundtrips_and_retry_exhaustion_is_terminal(tmp_path):
    plan = compile_opportunity_mission(_opportunity())
    with JarvisStateStore(tmp_path / "missions.db") as store:
        scheduler = MissionScheduler(store)
        scheduler.create(plan)
        resumed = scheduler.resume(plan.mission_id)
        assert resumed == plan
        task_id = plan.tasks[0].task_id
        for _ in range(3):
            plan = scheduler.set_task_state(plan, task_id, TaskState.FAILED_RETRYABLE)
        assert plan.tasks[0].state is TaskState.FAILED_TERMINAL
        assert plan.tasks[0].retry_count == 3


def test_worker_matching_distinguishes_ready_waiting_dynamic_and_unavailable():
    registry = MissionWorkerRegistry()
    internal = MissionTask(
        "internal", "judge", "independent_judge",
        executor_capability="jarvis:judge:independent_judge",
        asset_kind="source_code",
    )
    assert registry.match(internal).execution_class is ExecutionClass.INTERNAL_EXECUTOR

    ghidra = MissionTask(
        "ghidra", "binary", "analyze",
        executor_capability="Ghidra:headless-binary-analysis",
        asset_kind="executable",
    )
    waiting = registry.match(ghidra)
    assert waiting.disposition is CapabilityDisposition.WAITING_FOR_PREREQUISITE
    ready = registry.match(
        ghidra,
        availability=CapabilityAvailability(artifact_available=True, sandbox_available=True),
    )
    assert ready.disposition is CapabilityDisposition.READY
    assert ready.execution_class is ExecutionClass.REAL_EXECUTOR

    network = MissionTask(
        "nmap", "network", "fingerprint",
        executor_capability="nmap:bounded-service-fingerprinting",
        asset_kind="domain",
    )
    dynamic = registry.match(network)
    assert dynamic.disposition is CapabilityDisposition.WAITING_FOR_APPROVAL
    assert dynamic.execution_class is ExecutionClass.DYNAMIC_POLICY_EXECUTOR

    missing = MissionTask(
        "missing", "binary", "analyze",
        executor_capability="not-installed:no-backend",
        asset_kind="executable",
    )
    assert registry.match(missing).disposition is CapabilityDisposition.UNAVAILABLE
