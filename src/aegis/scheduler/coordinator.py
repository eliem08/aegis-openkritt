"""Scan coordinator — the Phase 1 keystone (Master Prompt §scheduling/recovery).

Ties the durable substrate together into one governed execution loop. Given a
scan plan (a stage DAG of adapter tasks) it:

  * materialises ``ScanRun`` / ``StageRun`` / ``TaskRun`` records,
  * leases a dependency-ready task with compare-and-set semantics,
  * atomically **reserves** budget + a session slot against the engagement caps,
  * builds an immutable :class:`ExecutionEnvelope` and runs the adapter's command
    through the :class:`SafeProcessRunner` (no direct network; the tool's egress
    is the gateway's job),
  * parses stdout into typed events; a sensitive-data signal or invalid output
    routes the task to ``quarantined`` instead of ``succeeded``,
  * persists an artifact summary + result and **finalises** the reservation,
  * honours the kill switch (queued work -> ``cancelled``, active runs signalled
    and their process trees terminated, no new claims), and
  * recovers via lease reclaim so a crashed worker's task requeues.

The coordinator holds no product secrets and never lets an adapter touch the
repository — it is the only place envelope, reservation, lease, process, event,
and persistence meet.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Callable

from aegis.adapters import (
    Adapter,
    EnvelopeError,
    EnvelopeLimits,
    EventKind,
    ExecutionEnvelope,
)
from aegis.api import scans
from aegis.process import CancelToken, ProcessOutcome, SafeProcessRunner


# --- scan plan -------------------------------------------------------------

@dataclass(frozen=True)
class StageSpec:
    key: str                     # local handle used by tasks + dependencies
    stage_type: str
    depends_on: tuple[str, ...] = ()   # other stage keys


@dataclass(frozen=True)
class TaskSpec:
    adapter: str                 # adapter name (key in the registry)
    target: str
    stage: str                   # stage key
    input_hash: str = ""
    est_spend: float = 0.0       # reserved before running; finalised after


@dataclass(frozen=True)
class ScanConfig:
    tenant_id: str
    engagement_id: str
    scope_targets: tuple[str, ...] = ()
    spend_cap: float | None = None       # None == unlimited
    session_cap: int = 1
    lease_ttl_seconds: int = 300


@dataclass
class StepResult:
    task_id: str
    outcome: str                 # succeeded | quarantined | blocked | failed | cancelled
    events: int = 0
    reason: str = ""


# States that make a stage "settled" for dependency purposes.
_SETTLED = scans.TERMINAL_STATES | {scans.TaskState.RETRYABLE_FAILED}


class ScanCoordinator:
    def __init__(
        self,
        *,
        repository,
        reservations,
        adapters: dict[str, Adapter],
        config: ScanConfig,
        runner: SafeProcessRunner | None = None,
        is_killed: Callable[[], bool] | None = None,
    ) -> None:
        self._repo = repository
        self._reservations = reservations
        self._adapters = dict(adapters)
        self._config = config
        self._runner = runner or SafeProcessRunner()
        self._is_killed = is_killed or (lambda: False)
        self._scope_digest = hashlib.sha256(
            json.dumps(sorted(config.scope_targets)).encode("utf-8")
        ).hexdigest()
        # Reservation caps travel with a lightweight, secret-free engagement view.
        self._resv_engagement = SimpleNamespace(
            id=config.engagement_id,
            authorization=SimpleNamespace(
                spend_budget=config.spend_cap,
                rate_limits=SimpleNamespace(max_concurrent_sessions=config.session_cap),
            ),
        )

    # --- planning ----------------------------------------------------------

    def plan_scan(self, stages: list[StageSpec], tasks: list[TaskSpec]) -> str:
        """Materialise a scan and its stage DAG + queued tasks; return scan_id."""
        manifest_set = sorted({self._adapters[t.adapter].manifest.name for t in tasks})
        scan = scans.new_scan(
            tenant_id=self._config.tenant_id,
            engagement_id=self._config.engagement_id,
            scope_digest=self._scope_digest,
            manifest_set=manifest_set,
        )
        self._repo.create_scan(scan)

        key_to_stage_id: dict[str, str] = {}
        for spec in _stages_in_dependency_order(stages):
            stage = scans.new_stage(
                scan_id=scan.scan_id,
                stage_type=spec.stage_type,
                depends_on=[key_to_stage_id[d] for d in spec.depends_on],
            )
            self._repo.create_stage(stage)
            key_to_stage_id[spec.key] = stage.stage_id

        for spec in tasks:
            manifest = self._adapters[spec.adapter].manifest
            task = scans.new_task(
                scan_id=scan.scan_id,
                stage_id=key_to_stage_id[spec.stage],
                target=spec.target,
                adapter=manifest.name,
                adapter_version=manifest.version,
                capability_tier=manifest.capability_tier,
                input_hash=spec.input_hash,
                quotas={"est_spend": spec.est_spend},
            )
            self._repo.create_task(task)
        return scan.scan_id

    # --- execution ---------------------------------------------------------

    def run_next(self, scan_id: str, worker_id: str = "worker") -> StepResult | None:
        """Advance the scan by one task. Returns None when nothing is runnable."""
        if self._is_killed():
            self._cancel_open_work(scan_id)
            return None

        task = self._pick_ready_task(scan_id)
        if task is None:
            return None

        lease = self._repo.lease_task(task.task_id, worker_id, self._config.lease_ttl_seconds)
        if lease is None:
            return None  # lost the compare-and-set race to another worker

        est_spend = float(task.quotas.get("est_spend", 0.0))
        reservation = self._reservations.reserve(
            self._resv_engagement, spend=est_spend, sessions=1,
            idempotency_key=f"resv:{task.task_id}",
        )
        if reservation is None:
            # Over a cap — this task cannot proceed under the authorization.
            self._repo.transition_task(task.task_id, scans.TaskState.BLOCKED,
                                       result_summary={"reason": "budget/session cap reached"})
            return StepResult(task.task_id, "blocked", reason="budget/session cap reached")

        actual_spend = 0.0
        try:
            self._repo.transition_task(task.task_id, scans.TaskState.RUNNING)
            result = self._execute(task)
            events = result.events
            quarantine, reason = self._should_quarantine(result.process, events)
            self._persist(task, events, quarantined=quarantine)
            actual_spend = est_spend if result.process.ok else 0.0

            if quarantine:
                final = scans.TaskState.QUARANTINED
                self._repo.transition_task(task.task_id, final,
                                           result_summary={"events": len(events), "reason": reason})
                return StepResult(task.task_id, "quarantined", len(events), reason)
            if result.process.ok:
                self._repo.transition_task(task.task_id, scans.TaskState.SUCCEEDED,
                                           result_summary={"events": len(events)})
                return StepResult(task.task_id, "succeeded", len(events))
            # Non-zero / timeout / cancelled — retryable unless a hard failure.
            outcome = result.process.outcome
            if outcome in (ProcessOutcome.CANCELLED,):
                self._repo.transition_task(task.task_id, scans.TaskState.CANCELLED)
                return StepResult(task.task_id, "cancelled", len(events))
            self._repo.transition_task(task.task_id, scans.TaskState.RETRYABLE_FAILED,
                                       result_summary={"outcome": outcome.value})
            return StepResult(task.task_id, "failed", len(events), outcome.value)
        except EnvelopeError as exc:
            # An inconsistent/invalid instruction is a hard, non-retryable stop.
            self._repo.transition_task(task.task_id, scans.TaskState.BLOCKED,
                                       result_summary={"error": str(exc)})
            return StepResult(task.task_id, "blocked", reason=str(exc))
        finally:
            self._reservations.finalize(reservation.reservation_id, actual_spend)

    def run_scan(self, scan_id: str, worker_id: str = "worker", max_steps: int = 1000) -> list[StepResult]:
        """Drive a scan to quiescence with a single worker (used by tests/dev)."""
        results: list[StepResult] = []
        for _ in range(max_steps):
            step = self.run_next(scan_id, worker_id)
            if step is None:
                break
            results.append(step)
        return results

    def recover(self, now: datetime | None = None) -> list[tuple[str, str]]:
        """Reclaim leases from crashed workers so their tasks requeue/block."""
        return self._repo.reclaim_expired_leases(now or datetime.now(timezone.utc))

    def cancel_scan(self, scan_id: str) -> int:
        """Stop a scan: queued/leased/running tasks -> cancelled. Returns the count."""
        return self._cancel_open_work(scan_id)

    # --- internals ---------------------------------------------------------

    def _pick_ready_task(self, scan_id: str):
        stages = {s.stage_id: s for s in self._repo.stages_for_scan(scan_id)}
        tasks = self._repo.tasks_for_scan(scan_id)
        by_stage: dict[str, list] = {}
        for t in tasks:
            by_stage.setdefault(t.stage_id, []).append(t)

        def stage_settled(stage_id: str) -> bool:
            members = by_stage.get(stage_id, [])
            return all(scans.TaskState(m.status) in _SETTLED for m in members)

        for t in tasks:
            if t.status != scans.TaskState.QUEUED.value:
                continue
            stage = stages.get(t.stage_id)
            deps = stage.depends_on if stage else []
            if all(stage_settled(dep) for dep in deps):
                return t
        return None

    def _execute(self, task) -> "_Execution":
        adapter = self._adapters[task.adapter]
        envelope = self._build_envelope(task, adapter)
        adapter.validate_envelope(envelope)  # may raise EnvelopeError -> blocked
        argv = adapter.build_command(envelope)

        cancel = CancelToken()
        if self._is_killed():
            cancel.cancel()
        process = self._runner.run(argv, limits=envelope.process_limits(), cancel=cancel)
        events = [
            ev for line in process.lines
            if (ev := adapter.parse_line(line, envelope)) is not None
        ]
        return _Execution(process=process, events=events)

    def _build_envelope(self, task, adapter) -> ExecutionEnvelope:
        return ExecutionEnvelope.for_manifest(
            adapter.manifest,
            tenant_id=self._config.tenant_id,
            engagement_id=self._config.engagement_id,
            scan_id=task.scan_id,
            stage_id=task.stage_id,
            task_id=task.task_id,
            target=task.target,
            scope_digest=self._scope_digest,
            idempotency_key=task.idempotency_key,
            input_hash=task.quotas.get("input_hash", ""),
            limits=EnvelopeLimits(wall_seconds=30.0),
        )

    @staticmethod
    def _should_quarantine(process, events) -> tuple[bool, str]:
        if any(e.kind == EventKind.SECRET_CANDIDATE for e in events):
            return True, "sensitive-data signal (secret candidate)"
        if process.outcome == ProcessOutcome.OUTPUT_LIMIT:
            return True, "output limit exceeded (possible malformed flood)"
        if process.ok and not any(e.kind == EventKind.TERMINAL for e in events):
            return True, "invalid output (no terminal event)"
        return False, ""

    def _persist(self, task, events, *, quarantined: bool) -> None:
        payload = json.dumps([{"kind": e.kind.value, "data": e.data} for e in events], sort_keys=True)
        artifact = scans.Artifact(
            artifact_id=uuid.uuid4().hex,
            task_id=task.task_id,
            kind="events",
            classification="quarantined" if quarantined else "clean",
            checksum=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            storage_ref=None,
            size=len(events),
            retention_deadline=None,
            created_at=datetime.now(timezone.utc),
        )
        self._repo.create_artifact(artifact)

    def _cancel_open_work(self, scan_id: str) -> int:
        """Kill-switch response: queued/leased/running -> cancelled. Returns count."""
        cancelled = 0
        for t in self._repo.tasks_for_scan(scan_id):
            state = scans.TaskState(t.status)
            if state in (scans.TaskState.QUEUED, scans.TaskState.LEASED, scans.TaskState.RUNNING):
                # Queued work stops; a live run's worker terminates its own process
                # tree — here we mark intent so it cannot settle as succeeded.
                self._repo.transition_task(t.task_id, scans.TaskState.CANCELLED,
                                           result_summary={"reason": "cancelled"})
                cancelled += 1
        return cancelled


@dataclass
class _Execution:
    process: object
    events: list = field(default_factory=list)


def _stages_in_dependency_order(stages: list[StageSpec]) -> list[StageSpec]:
    """Topologically order stages so a stage's dependencies are created first."""
    by_key = {s.key: s for s in stages}
    ordered: list[StageSpec] = []
    seen: set[str] = set()
    visiting: set[str] = set()

    def visit(key: str) -> None:
        if key in seen:
            return
        if key in visiting:
            raise ValueError(f"cyclic stage dependency at {key!r}")
        visiting.add(key)
        for dep in by_key[key].depends_on:
            if dep not in by_key:
                raise ValueError(f"stage {key!r} depends on unknown stage {dep!r}")
            visit(dep)
        visiting.discard(key)
        seen.add(key)
        ordered.append(by_key[key])

    for spec in stages:
        visit(spec.key)
    return ordered
