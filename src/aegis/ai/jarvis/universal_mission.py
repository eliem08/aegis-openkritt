"""Compile universal hunt candidates into resumable evidence-first missions."""

from __future__ import annotations

from hashlib import sha256

from .hunt_lanes import lane_for_family
from .mission_scheduler import MissionPlan, MissionTask
from .weakness_catalog import HuntCandidate


def _candidate_key(candidate: HuntCandidate) -> str:
    material = f"{candidate.family.family_id}\x1f{candidate.surface}\x1f{candidate.severity.value}"
    return sha256(material.encode()).hexdigest()[:12]


def compile_candidate_mission(
    *,
    candidate: HuntCandidate,
    scope_digest: str,
    mission_prefix: str = "hunt",
) -> MissionPlan:
    lane = lane_for_family(candidate.family)
    key = _candidate_key(candidate)
    mission_id = f"{mission_prefix}-{key}"
    tasks: list[MissionTask] = []
    previous: str | None = None
    for index, action in enumerate(lane.analysis_steps):
        task_id = f"{key}-{index:02d}-{action}"
        role = (
            "judge"
            if action == "independent_judge"
            else "evidence"
            if "evidence" in action
            else "reproduction"
            if lane.local_validation and index > 0
            else "research"
        )
        payload = {
            "family_id": candidate.family.family_id,
            "surface": candidate.surface,
            "severity": candidate.severity.value,
            "lane_id": lane.lane_id,
            "local_only": lane.local_validation,
            "requires_human_approval": bool(lane.state_change_possible and index > 0),
            "evidence_required": list(lane.evidence_required),
            "expected_net_usd": candidate.expected_net_usd,
        }
        tasks.append(
            MissionTask(
                task_id=task_id,
                agent_role=role,
                action=action,
                dependencies=(previous,) if previous else (),
                payload=payload,
            )
        )
        previous = task_id

    evidence_task = f"{key}-{len(tasks):02d}-assemble_evidence"
    tasks.append(
        MissionTask(
            task_id=evidence_task,
            agent_role="evidence",
            action="assemble_evidence_bundle",
            dependencies=(previous,) if previous else (),
            payload={
                "family_id": candidate.family.family_id,
                "surface": candidate.surface,
                "severity": candidate.severity.value,
                "required": list(lane.evidence_required),
            },
        )
    )
    return MissionPlan(
        mission_id=mission_id,
        scope_digest=scope_digest,
        objective=(
            f"Validate {candidate.family.title} on {candidate.surface} with "
            f"{lane.lane_id} evidence controls"
        ),
        tasks=tuple(tasks),
    )
