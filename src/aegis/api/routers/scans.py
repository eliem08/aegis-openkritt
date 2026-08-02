"""Scan lifecycle: plan a scan, list/read it, cancel it, and let workers drive
task execution — all tenant-scoped (Phase 1 API surface).

Roles: an **agent** plans and reads scans within its tenant; an **operator** may
cancel; a **worker** (the execution identity) runs tasks and heartbeats leases.
Raw artifact payloads are never in normal responses — an operator must invoke an
explicit quarantine-review to obtain a reference.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from ..config import ApiPrincipal, ControlPlaneConfig
from ..dependencies import get_config, get_store, tenant_matches
from ..reservations import ReservationService
from ..schemas import (
    ArtifactOut,
    ArtifactRawOut,
    ArtifactReviewIn,
    CancelOut,
    HeartbeatOut,
    RecoverOut,
    ScanCreateIn,
    ScanDetailOut,
    ScanOut,
    StageOut,
    StepOut,
    TaskOut,
)
from ..security import require_agent, require_operator, require_worker
from ..store import Engagement, EngagementStore

router = APIRouter(tags=["scans"])


# --- shared helpers --------------------------------------------------------

def get_repository(request: Request):
    """The durable repository, or 503 — scans require persistence."""
    repo = getattr(request.app.state, "repository", None)
    if repo is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="scans require a configured database (set AEGIS_DB_URL or AEGIS_DB_PATH)",
        )
    return repo


def get_adapters(request: Request) -> dict:
    return getattr(request.app.state, "adapters", {})


def _coordinator_for(engagement: Engagement, repo, adapters):
    from aegis.scheduler import ScanConfig, ScanCoordinator

    a = engagement.authorization
    config = ScanConfig(
        tenant_id=engagement.tenant_id,
        engagement_id=engagement.id,
        scope_targets=tuple(a.targets),
        spend_cap=a.spend_budget,
        session_cap=a.rate_limits.max_concurrent_sessions,
    )
    return ScanCoordinator(
        repository=repo, reservations=ReservationService(repo), adapters=adapters, config=config,
    )


def _owned_scan(scan_id: str, principal: ApiPrincipal, repo, config: ControlPlaneConfig):
    """Fetch a scan the caller's tenant may see, or 404 (no cross-tenant leak)."""
    scan = repo.get_scan(scan_id)
    if scan is None or (not config.is_single_tenant_compat and scan.tenant_id != principal.tenant_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return scan


def _engagement_for_scan(scan, store: EngagementStore) -> Engagement:
    engagement = store.get(scan.engagement_id)
    if engagement is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement for scan not found")
    return engagement


# --- planning + inspection (agent) -----------------------------------------

@router.post("/scans", response_model=ScanOut, status_code=status.HTTP_201_CREATED,
             summary="Plan a scan (stage DAG of adapter tasks) within an engagement")
def create_scan(
    body: ScanCreateIn,
    store: EngagementStore = Depends(get_store),
    config: ControlPlaneConfig = Depends(get_config),
    repo=Depends(get_repository),
    adapters: dict = Depends(get_adapters),
    principal: ApiPrincipal = Depends(require_agent),
) -> ScanOut:
    engagement = store.get(body.engagement_id)
    if engagement is None or not tenant_matches(principal, engagement, config):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement not found")
    if not engagement.is_active:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="engagement is closed")

    unknown = sorted({t.adapter for t in body.tasks} - set(adapters))
    if unknown:
        raise HTTPException(status_code=422, detail=f"unknown adapters: {', '.join(unknown)}")

    # Every task target must be inside the signed authorization (defense in depth;
    # the gateway re-enforces scope at execution time).
    authorized = set(engagement.authorization.targets)
    out_of_scope = sorted({t.target for t in body.tasks} - authorized)
    if out_of_scope:
        raise HTTPException(status_code=422, detail=f"targets not in authorization: {', '.join(out_of_scope)}")

    stage_keys = {s.key for s in body.stages}
    bad = sorted({t.stage for t in body.tasks} - stage_keys)
    if bad:
        raise HTTPException(status_code=422, detail=f"tasks reference unknown stages: {', '.join(bad)}")

    from aegis.scheduler import StageSpec, TaskSpec

    coordinator = _coordinator_for(engagement, repo, adapters)
    try:
        scan_id = coordinator.plan_scan(
            [StageSpec(s.key, s.stage_type, tuple(s.depends_on)) for s in body.stages],
            [TaskSpec(t.adapter, t.target, t.stage, t.input_hash, t.est_spend) for t in body.tasks],
        )
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=422, detail=f"invalid scan plan: {exc}")
    return ScanOut.from_scan(repo.get_scan(scan_id))


@router.get("/scans", response_model=list[ScanOut], summary="List scans in the caller's tenant")
def list_scans(
    config: ControlPlaneConfig = Depends(get_config),
    repo=Depends(get_repository),
    principal: ApiPrincipal = Depends(require_agent),
) -> list[ScanOut]:
    tenant = None if config.is_single_tenant_compat else principal.tenant_id
    return [ScanOut.from_scan(s) for s in repo.scans_for_tenant(tenant)]


@router.get("/scans/{scan_id}", response_model=ScanDetailOut,
            summary="Read a scan with its stages, tasks, and sanitized artifacts")
def get_scan(
    scan_id: str,
    config: ControlPlaneConfig = Depends(get_config),
    repo=Depends(get_repository),
    principal: ApiPrincipal = Depends(require_agent),
) -> ScanDetailOut:
    scan = _owned_scan(scan_id, principal, repo, config)
    tasks = repo.tasks_for_scan(scan_id)
    artifacts = [a for t in tasks for a in repo.artifacts_for_task(t.task_id)]
    base = ScanOut.from_scan(scan).model_dump()
    return ScanDetailOut(
        **base,
        stages=[StageOut.from_stage(s) for s in repo.stages_for_scan(scan_id)],
        tasks=[TaskOut.from_task(t) for t in tasks],
        artifacts=[ArtifactOut.from_artifact(a) for a in artifacts],
    )


# --- control (operator) ----------------------------------------------------

@router.post("/scans/{scan_id}/cancel", response_model=CancelOut,
             summary="Cancel a scan: stop queued/active tasks")
def cancel_scan(
    scan_id: str,
    store: EngagementStore = Depends(get_store),
    config: ControlPlaneConfig = Depends(get_config),
    repo=Depends(get_repository),
    adapters: dict = Depends(get_adapters),
    principal: ApiPrincipal = Depends(require_operator),
) -> CancelOut:
    scan = _owned_scan(scan_id, principal, repo, config)
    engagement = _engagement_for_scan(scan, store)
    coordinator = _coordinator_for(engagement, repo, adapters)
    return CancelOut(scan_id=scan_id, cancelled=coordinator.cancel_scan(scan_id))


# --- execution (worker) ----------------------------------------------------

@router.post("/scans/{scan_id}/run-next", response_model=StepOut,
             summary="Worker: lease and run the next ready task through the coordinator")
def run_next(
    scan_id: str,
    store: EngagementStore = Depends(get_store),
    config: ControlPlaneConfig = Depends(get_config),
    repo=Depends(get_repository),
    adapters: dict = Depends(get_adapters),
    principal: ApiPrincipal = Depends(require_worker),
) -> StepOut:
    scan = _owned_scan(scan_id, principal, repo, config)
    engagement = _engagement_for_scan(scan, store)
    if not engagement.is_active:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="engagement is closed")
    coordinator = _coordinator_for(engagement, repo, adapters)
    step = coordinator.run_next(scan_id, worker_id=principal.name)
    if step is None:
        return StepOut(ran=False, reason="no runnable task")
    return StepOut(ran=True, task_id=step.task_id, outcome=step.outcome,
                   events=step.events, reason=step.reason)


@router.post("/scans/{scan_id}/recover", response_model=RecoverOut,
             summary="Worker: reclaim this scan's expired leases (restart recovery)")
def recover_scan(
    scan_id: str,
    config: ControlPlaneConfig = Depends(get_config),
    repo=Depends(get_repository),
    adapters: dict = Depends(get_adapters),
    principal: ApiPrincipal = Depends(require_worker),
) -> RecoverOut:
    scan = _owned_scan(scan_id, principal, repo, config)
    scan_task_ids = {t.task_id for t in repo.tasks_for_scan(scan_id)}
    reclaimed = [tid for tid, _status in repo.reclaim_expired_leases() if tid in scan_task_ids]
    return RecoverOut(scan_id=scan_id, reclaimed=reclaimed)


@router.post("/tasks/{task_id}/heartbeat", response_model=HeartbeatOut,
             summary="Worker: extend the lease on a task it owns")
def heartbeat_task(
    task_id: str,
    config: ControlPlaneConfig = Depends(get_config),
    repo=Depends(get_repository),
    principal: ApiPrincipal = Depends(require_worker),
) -> HeartbeatOut:
    task = repo.get_task(task_id)
    if task is not None:
        _owned_scan(task.scan_id, principal, repo, config)  # tenant check (404 if cross-tenant)
    if task is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="task not found")
    extended = repo.heartbeat_task(task_id, owner=principal.name)
    return HeartbeatOut(task_id=task_id, extended=extended)


# --- raw artifact access (operator + explicit review) ----------------------

@router.post("/artifacts/{artifact_id}/raw", response_model=ArtifactRawOut,
             summary="Operator: obtain a raw artifact reference via quarantine review")
def review_artifact(
    artifact_id: str,
    body: ArtifactReviewIn,
    config: ControlPlaneConfig = Depends(get_config),
    repo=Depends(get_repository),
    principal: ApiPrincipal = Depends(require_operator),
) -> ArtifactRawOut:
    if body.action != "quarantine_review":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="raw access requires an explicit quarantine_review action")
    artifact = repo.get_artifact(artifact_id)
    if artifact is not None:
        task = repo.get_task(artifact.task_id)
        if task is not None:
            _owned_scan(task.scan_id, principal, repo, config)  # tenant check
    if artifact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="artifact not found")
    return ArtifactRawOut(
        artifact_id=artifact.artifact_id,
        classification=artifact.classification,
        storage_ref=artifact.storage_ref,
        note=("raw payloads are stored out-of-band beginning Phase 2; this endpoint "
              "is the audited operator gate for retrieving them"),
    )
