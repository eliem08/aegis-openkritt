"""Compile canonical hunt opportunities into resumable evidence-first missions."""

from __future__ import annotations

from hashlib import sha256

from aegis.scheduler.profit import HuntOpportunity, score

from .hunt_lanes import HuntLane, lane_for_family
from .mission_scheduler import MissionPlan, MissionTask, TaskState
from .weakness_catalog import UNIVERSAL_FAMILIES, HuntCandidate


def _opportunity_key(opportunity: HuntOpportunity) -> str:
    material = "\x1f".join((
        opportunity.opportunity_id,
        opportunity.asset_id,
        opportunity.attack_surface,
        opportunity.weakness_family,
    ))
    return sha256(material.encode()).hexdigest()[:12]


def _lane(opportunity: HuntOpportunity) -> HuntLane:
    family = next(
        (item for item in UNIVERSAL_FAMILIES
         if item.family_id == opportunity.weakness_family),
        None,
    )
    if family is not None:
        return lane_for_family(family)
    return HuntLane(
        lane_id="offline-analysis",
        analysis_steps=("source_review", "negative_control", "independent_judge"),
        evidence_required=("source_path", "negative_control"),
        local_validation=False,
    )


def _initial_state(opportunity: HuntOpportunity) -> TaskState:
    state = opportunity.prerequisite_state.strip().lower()
    if state in {"unavailable", TaskState.UNAVAILABLE.value}:
        return TaskState.UNAVAILABLE
    if state not in {"", "ready", "available"}:
        return TaskState.WAITING_FOR_PREREQUISITE
    return TaskState.PENDING


def compile_opportunity_mission(
    opportunity: HuntOpportunity,
    *,
    mission_prefix: str = "hunt",
) -> MissionPlan:
    """Compile one opportunity; it never authorizes or executes its tasks."""
    lane = _lane(opportunity)
    key = _opportunity_key(opportunity)
    mission_id = f"{mission_prefix}-{key}"
    tasks: list[MissionTask] = []
    previous: str | None = None
    actions = (*lane.analysis_steps, "assemble_evidence_bundle")
    total_cost = float(score(opportunity.features).total_cost)
    task_cost = total_cost / max(1, len(actions))
    initial_state = _initial_state(opportunity)

    for index, action in enumerate(actions):
        task_id = f"{key}-{index:02d}-{action}"
        role = (
            "judge" if action == "independent_judge"
            else "evidence" if "evidence" in action
            else "reproduction" if lane.local_validation and index > 0
            else "research"
        )
        state_change = bool(lane.state_change_possible and index > 0)
        tasks.append(MissionTask(
            task_id=task_id,
            agent_role=role,
            action=action,
            dependencies=(previous,) if previous else (),
            state=initial_state,
            payload={
                "family_id": opportunity.weakness_family,
                "surface": opportunity.attack_surface,
                "lane_id": lane.lane_id,
                "local_only": lane.local_validation,
                "requires_human_approval": state_change,
            },
            opportunity_id=opportunity.opportunity_id,
            asset_id=opportunity.asset_id,
            asset_kind=opportunity.asset_kind,
            asset_locator=opportunity.asset_locator,
            executor_capability=f"jarvis:{role}:{action}",
            risk="controlled_state_change" if state_change else "offline",
            prerequisites=(opportunity.prerequisite_state,)
            if opportunity.prerequisite_state not in {"", "ready"} else (),
            expected_requests=0,
            expected_cost_usd=task_cost,
            evidence_required=tuple(lane.evidence_required),
            success_criteria=("required evidence is persisted with provenance",),
            failure_criteria=("required evidence is absent or contradictory",),
            stop_loss_criteria=(
                "authorization expired",
                "budget exhausted",
                "no new information",
            ),
            idempotency_key=f"{mission_id}:{task_id}",
        ))
        previous = task_id

    result = score(opportunity.features)
    return MissionPlan(
        mission_id=mission_id,
        scope_digest=opportunity.scope_digest,
        objective=(
            f"Validate {opportunity.weakness_family or 'security hypothesis'} on "
            f"{opportunity.asset_kind}:{opportunity.asset_locator} with {lane.lane_id} controls"
        ),
        tasks=tuple(tasks),
        opportunity_id=opportunity.opportunity_id,
        program_id=opportunity.program_id,
        asset_id=opportunity.asset_id,
        asset_kind=opportunity.asset_kind,
        authorization_id=opportunity.authorization_id,
        expected_net_value_usd=float(result.net_expected_value),
    )


def compile_candidate_mission(
    *,
    candidate: HuntCandidate,
    scope_digest: str,
    mission_prefix: str = "hunt",
) -> MissionPlan:
    """Backward-compatible adapter from the former Jarvis candidate contract."""
    key = sha256(
        f"{candidate.family.family_id}\x1f{candidate.surface}\x1f{candidate.severity.value}".encode()
    ).hexdigest()[:12]
    opportunity = candidate.to_opportunity(
        opportunity_id=f"candidate:{key}",
        asset_kind="source_code",
        scope_digest=scope_digest,
        provenance=("aegis.ai.jarvis.compile_candidate_mission",),
    )
    return compile_opportunity_mission(opportunity, mission_prefix=mission_prefix)


__all__ = ["compile_candidate_mission", "compile_opportunity_mission"]
