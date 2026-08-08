"""Persistence adapter for the canonical live Jarvis seam.

This deliberately reuses :class:`JarvisStateStore` and its existing durable mission
snapshot table. It does not introduce a second database. Finding snapshots are stored with
a reserved ``finding::`` mission-id prefix so older Jarvis databases remain compatible and
can be migrated later without losing evidence.
"""

from __future__ import annotations

import os
from dataclasses import asdict
from pathlib import Path

from .jarvis.mission_scheduler import (
    MissionPlan,
    MissionScheduler,
    MissionTask,
    TaskState,
)
from .jarvis.state_store import JarvisStateStore, MissionSnapshot

_FINDING_PREFIX = "finding::"
_MISSION_PREFIX = "hunt::"


def state_db_path() -> str:
    return os.environ.get("AEGIS_JARVIS_DB", "reports/jarvis_state.db").strip() or \
        "reports/jarvis_state.db"


def _store(path: str | Path | None = None) -> JarvisStateStore:
    p = str(path or state_db_path())
    if p != ":memory:":
        Path(p).parent.mkdir(parents=True, exist_ok=True)
    return JarvisStateStore(p)


def persist_finding(row: dict, *, repository: str = "", scope_digest: str = "",
                    path: str | Path | None = None) -> None:
    """Persist canonical lifecycle metadata, then upsert its security-graph projection."""
    state = row.get("jarvis") or {}
    finding_id = str(state.get("finding_id") or "")
    if not finding_id:
        return
    answer = row.get("json_answer") or {}
    payload = {
        "repository": repository,
        "weakness": str(answer.get("vulnerability_type") or "")[:120],
        "location": f"{answer.get('file_path','')}:{answer.get('line','')}",
        "summary": str(answer.get("summary") or "")[:240],
        "jarvis": state,
        "triage": row.get("triage") or {},
        "reproduction": row.get("reproduction") or {},
    }
    with _store(path) as store:
        store.save_mission(MissionSnapshot(
            mission_id=_FINDING_PREFIX + finding_id,
            scope_digest=scope_digest or "source-review",
            objective="persist canonical finding lifecycle",
            state=str(state.get("stage") or "candidate"),
            payload=payload,
            cursor=0,
        ))
    if repository:
        try:
            from .jarvis_graph import persist_row_graph
            persist_row_graph(row, repository, path=path)
        except Exception:
            pass


def load_finding(finding_id: str, *, path: str | Path | None = None) -> dict | None:
    with _store(path) as store:
        snap = store.load_mission(_FINDING_PREFIX + finding_id)
    return dict(snap.payload) if snap is not None else None


def learned_probabilities(program_id: str, weakness: str, *,
                          path: str | Path | None = None) -> dict[str, float | int]:
    if not program_id or not weakness:
        return {"samples": 0, "acceptance": 0.5, "uniqueness": 0.5,
                "mean_payout_usd": 0.0, "mean_cost_usd": 0.0}
    with _store(path) as store:
        prior = store.learned_prior(program_id, weakness)
    return {
        "samples": prior.samples,
        "acceptance": prior.acceptance_probability,
        "uniqueness": prior.uniqueness_probability,
        "mean_payout_usd": prior.mean_payout_usd,
        "mean_cost_usd": prior.mean_cost_usd,
    }


def build_live_mission(*, repository: str, scope_digest: str) -> MissionPlan:
    tasks = (
        MissionTask("authorize", "program_policy", "verify_target_authorization"),
        MissionTask("scan", "static_analysis", "deterministic_scan", ("authorize",)),
        MissionTask("analyze", "hypothesis", "source_reasoning", ("scan",)),
        MissionTask("validate", "evidence", "citation_validation", ("analyze",)),
        MissionTask("economics", "profitability", "net_value_allocation", ("validate",)),
        MissionTask("skeptic", "judge", "hostile_review", ("economics",)),
        MissionTask("reproduce", "reproduction", "local_reproduction", ("skeptic",)),
        MissionTask("report", "report", "human_review_package", ("reproduce",)),
    )
    return MissionPlan(
        mission_id=_MISSION_PREFIX + repository.replace("/", "__").lower(),
        scope_digest=scope_digest or "source-review",
        objective=f"authorized source review of {repository}",
        tasks=tasks,
    )


def checkpoint_phase(repository: str, phase: str, *, scope_digest: str = "",
                     payload: dict | None = None, path: str | Path | None = None) -> None:
    order = ("authorize", "scan", "analyze", "validate", "economics", "skeptic",
             "reproduce", "report")
    if phase not in order:
        return
    with _store(path) as store:
        scheduler = MissionScheduler(store)
        mission_id = _MISSION_PREFIX + repository.replace("/", "__").lower()
        plan = scheduler.resume(mission_id)
        if plan is None:
            plan = scheduler.create(build_live_mission(repository=repository,
                                                       scope_digest=scope_digest))
        target_index = order.index(phase)
        for task in plan.tasks:
            idx = order.index(task.task_id)
            if idx <= target_index and task.state is not TaskState.COMPLETE:
                plan = scheduler.set_task_state(plan, task.task_id, TaskState.COMPLETE)
        if payload:
            store.save_mission(MissionSnapshot(
                mission_id=mission_id + "::telemetry",
                scope_digest=scope_digest or plan.scope_digest,
                objective="live mission telemetry",
                state=phase,
                payload=dict(payload),
                cursor=target_index,
            ))


def mission_state(repository: str, *, path: str | Path | None = None) -> dict | None:
    with _store(path) as store:
        scheduler = MissionScheduler(store)
        plan = scheduler.resume(_MISSION_PREFIX + repository.replace("/", "__").lower())
    if plan is None:
        return None
    return {
        "mission_id": plan.mission_id,
        "scope_digest": plan.scope_digest,
        "state": plan.state,
        "cursor": plan.cursor,
        "tasks": [asdict(task) | {"state": task.state.value} for task in plan.tasks],
    }
