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
import time
import uuid
from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Callable

from aegis.adapters import (
    Adapter,
    DocumentAdapter,
    EnvelopeError,
    EnvelopeLimits,
    EventKind,
    ExecutionEnvelope,
)
from aegis.api import graph_serde, scans
from aegis.graph import Normalizer, merge_into, new_snapshot
from aegis.policy.scope import ScopeGuard
from aegis.process import CancelToken, ProcessOutcome, SafeProcessRunner


# --- scan plan -------------------------------------------------------------

@dataclass(frozen=True)
class StageSpec:
    key: str                     # local handle used by tasks + dependencies
    stage_type: str
    depends_on: tuple[str, ...] = ()   # blocking: must be settled first
    #: Streaming dependencies: this stage may start from validated incremental
    #: events while the producer is still running (Phase 2 §Stage graph).
    stream_from: tuple[str, ...] = ()
    min_stream_events: int = 1   # validated events required before starting


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
    sensitive_markers: tuple[str, ...] = ()   # tenant-configured sensitive canaries


@dataclass
class StepResult:
    task_id: str
    outcome: str                 # succeeded | quarantined | blocked | failed | cancelled
    events: int = 0
    reason: str = ""
    assets: int = 0              # assets merged into the graph
    rejected: int = 0            # out-of-scope / wildcard / unparseable emissions


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
        telemetry=None,
    ) -> None:
        self._repo = repository
        self._reservations = reservations
        self._adapters = dict(adapters)
        self._config = config
        self._runner = runner or SafeProcessRunner()
        self._is_killed = is_killed or (lambda: False)
        self._telemetry = telemetry
        self._scope_digest = hashlib.sha256(
            json.dumps(sorted(config.scope_targets)).encode("utf-8")
        ).hexdigest()
        # In-process mirror of the authorized allowlist; the normalizer refuses to
        # store anything outside it (the gateway enforces the same at request time).
        self._scope = ScopeGuard.from_authorization(list(config.scope_targets))
        # Sensitive-data ingestion gate: a match is quarantined, never normalized.
        from aegis.sensitive import ClassifierConfig, SensitiveDataClassifier

        self._classifier = SensitiveDataClassifier(
            ClassifierConfig(tenant_markers=tuple(config.sensitive_markers)))
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
                stream_from=[key_to_stage_id[d] for d in spec.stream_from],
                min_stream_events=spec.min_stream_events,
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
        _t0 = time.perf_counter()
        reservation = self._reservations.reserve(
            self._resv_engagement, spend=est_spend, sessions=1,
            idempotency_key=f"resv:{task.task_id}",
        )
        self._observe("reservation_latency", (time.perf_counter() - _t0) * 1000)
        if reservation is None:
            # Over a cap — this task cannot proceed under the authorization.
            self._count("policy_denials", reason="budget")
            self._repo.transition_task(task.task_id, scans.TaskState.BLOCKED,
                                       result_summary={"reason": "budget/session cap reached"})
            return StepResult(task.task_id, "blocked", reason="budget/session cap reached")

        actual_spend = 0.0
        try:
            self._repo.transition_task(task.task_id, scans.TaskState.RUNNING)
            with self._span("scan.task.run", adapter=task.adapter,
                            capability_tier=task.capability_tier, tenant_id=self._config.tenant_id):
                result = self._execute(task)
            events = result.events
            succeeded = self._result_succeeded(self._adapters[task.adapter], result.process)
            quarantine, reason = self._should_quarantine(result.process, events,
                                                         sensitive=result.sensitive)
            self._persist(task, events, quarantined=quarantine)
            actual_spend = est_spend if succeeded else 0.0

            if quarantine:
                # The streamed observations are marked quarantined and never
                # promoted, so nothing from this task reaches the asset graph.
                self._repo.set_observation_state(task.task_id, graph_serde.QUARANTINED)
                summary = {"events": len(events), "reason": reason}
                if result.sensitive:
                    # Only redacted classifications reach product data; an operator
                    # escalation is raised and report rendering is blocked.
                    summary["sensitive"] = result.sensitive_classifications
                    summary["escalation"] = "operator_review_required"
                    summary["report_blocked"] = True
                self._repo.transition_task(task.task_id, scans.TaskState.QUARANTINED,
                                           result_summary=summary)
                if result.sensitive:
                    category = (result.sensitive_classifications[0].get("category")
                                if result.sensitive_classifications else "unknown")
                    self._count("sensitive_quarantines", category=category)
                return StepResult(task.task_id, "quarantined", len(events), reason)
            if succeeded:
                graph = self._promote(task, result)
                self._repo.transition_task(task.task_id, scans.TaskState.SUCCEEDED,
                                           result_summary={"events": len(events), "graph": graph})
                return StepResult(task.task_id, "succeeded", len(events),
                                  assets=graph["assets"], rejected=graph["rejected"])
            # Non-zero / timeout / cancelled — retryable unless a hard failure.
            outcome = result.process.outcome
            if outcome in (ProcessOutcome.CANCELLED,):
                self._repo.transition_task(task.task_id, scans.TaskState.CANCELLED)
                return StepResult(task.task_id, "cancelled", len(events))
            self._repo.transition_task(task.task_id, scans.TaskState.RETRYABLE_FAILED,
                                       result_summary={"outcome": outcome.value})
            self._count("adapter_errors", adapter=task.adapter, version=task.adapter_version)
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
        reclaimed = self._repo.reclaim_expired_leases(now or datetime.now(timezone.utc))
        if reclaimed:
            self._count("lease_expiry", amount=len(reclaimed))
        return reclaimed

    # -- telemetry (no-ops unless a facade is wired) ------------------------

    _METRICS = {
        "reservation_latency": "RESERVATION_LATENCY", "policy_denials": "POLICY_DENIALS",
        "sensitive_quarantines": "SENSITIVE_QUARANTINES", "adapter_errors": "ADAPTER_ERRORS",
        "lease_expiry": "LEASE_EXPIRY", "snapshot_coverage": "SNAPSHOT_COVERAGE",
    }

    def _span(self, name: str, **attrs):
        return self._telemetry.span(name, **attrs) if self._telemetry is not None else nullcontext({})

    def _count(self, metric: str, *, amount: float = 1.0, **labels) -> None:
        if self._telemetry is None:
            return
        from aegis.observ import MetricNames

        self._telemetry.counter(getattr(MetricNames, self._METRICS[metric])).inc(amount, **labels)

    def _observe(self, metric: str, value: float, **labels) -> None:
        if self._telemetry is None:
            return
        from aegis.observ import MetricNames

        self._telemetry.histogram(getattr(MetricNames, self._METRICS[metric])).observe(value, **labels)

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
        progress = {p.task_id: p for p in self._repo.progress_for_scan(scan_id) if p}

        def stage_settled(stage_id: str) -> bool:
            members = by_stage.get(stage_id, [])
            return all(scans.TaskState(m.status) in _SETTLED for m in members)

        def stage_events(stage_id: str) -> int:
            return sum(progress[m.task_id].events
                       for m in by_stage.get(stage_id, []) if m.task_id in progress)

        for t in tasks:
            if t.status != scans.TaskState.QUEUED.value:
                continue
            stage = stages.get(t.stage_id)
            if stage is None:
                return t
            if not all(stage_settled(dep) for dep in stage.depends_on):
                continue
            # A streaming dependency needs either enough validated events to work
            # from, or to have finished — partial progress is enough to start.
            if not all(
                stage_settled(dep) or stage_events(dep) >= stage.min_stream_events
                for dep in stage.stream_from
            ):
                continue
            return t
        return None

    def _execute(self, task) -> "_Execution":
        """Run the adapter, streaming validated events as they arrive.

        Each line is parsed and normalized immediately and its observations are
        written **provisionally**, so a downstream stage can start from partial
        progress. They only join the asset graph when the task completes cleanly
        (see ``run_next``) — a quarantined stream is never promoted.
        """
        adapter = self._adapters[task.adapter]
        envelope = self._build_envelope(task, adapter)
        adapter.validate_envelope(envelope)  # may raise EnvelopeError -> blocked
        argv = adapter.build_command(envelope)

        cancel = CancelToken()
        if self._is_killed():
            cancel.cancel()

        normalizer = Normalizer(
            scope=self._scope, engagement_id=self._config.engagement_id, scan_id=task.scan_id,
            classifier=self._classifier,
        )
        execution = _Execution(process=None, events=[])

        def consume(event) -> None:
            if event is None:
                return
            execution.events.append(event)
            result = normalizer.normalize([event])
            if result.observations:
                self._repo.record_observations(result.observations, graph_serde.PROVISIONAL)
                merge_into(execution.assets, result.assets)
            if result.sensitive:
                # Never store the raw artifact; carry only redacted classifications
                # so run_next can quarantine the task and escalate.
                execution.sensitive = True
                execution.sensitive_classifications.extend(result.sensitive_classifications)
            execution.rejections += len(result.rejections)
            for rejection in result.rejections:
                execution.rejection_codes[rejection.reason] = \
                    execution.rejection_codes.get(rejection.reason, 0) + 1
            # Progress is recorded separately from completion: the task is still
            # running, but downstream stages can already see how far it has got.
            self._repo.record_progress(
                task.task_id, task.scan_id, stage_id=task.stage_id,
                events=len(execution.events), assets=len(execution.assets),
                rejected=execution.rejections,
            )

        is_document = isinstance(adapter, DocumentAdapter)

        def on_line(line: str) -> None:
            if not is_document:
                consume(adapter.parse_line(line, envelope))

        execution.process = self._runner.run(
            argv, limits=envelope.process_limits(), cancel=cancel, on_line=on_line,
        )
        if is_document:
            # SafeProcessRunner has already enforced the envelope's output caps.
            document = "\n".join(execution.process.lines)
            for event in adapter.parse_document(document, envelope):
                consume(event)
        if not any(event.kind == EventKind.TERMINAL for event in execution.events):
            consume(adapter.interpret_result(execution.process, envelope))
        return execution

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
    def _result_succeeded(adapter, process) -> bool:
        predicate = getattr(adapter, "result_succeeded", None)
        return bool(predicate(process)) if callable(predicate) else bool(process.ok)

    @staticmethod
    def _should_quarantine(process, events, *, sensitive: bool = False) -> tuple[bool, str]:
        if sensitive:
            return True, "sensitive data encountered (path cancelled)"
        if any(e.kind == EventKind.SECRET_CANDIDATE for e in events):
            return True, "sensitive-data signal (secret candidate)"
        if any(
            e.kind == EventKind.DIAGNOSTIC and bool(e.data.get("blocking"))
            for e in events
        ):
            return True, "invalid output (blocking parser diagnostic)"
        if process.outcome == ProcessOutcome.OUTPUT_LIMIT:
            return True, "output limit exceeded (possible malformed flood)"
        if process.ok and not any(e.kind == EventKind.TERMINAL for e in events):
            return True, "invalid output (no terminal event)"
        return False, ""

    def _promote(self, task, execution: "_Execution") -> dict:
        """Accept a cleanly-finished task's streamed output into the asset graph.

        The observations already exist (written provisionally as they streamed);
        promotion flips their state and merges the derived assets. Out-of-scope
        and wildcard emissions were rejected during streaming and only counted.
        """
        promoted = self._repo.set_observation_state(task.task_id, graph_serde.PROMOTED)
        self._repo.upsert_assets(execution.assets.values())
        counts = {
            "observations": promoted,
            "assets": len(execution.assets),
            "rejected": execution.rejections,
        }
        if execution.rejection_codes:
            counts["rejections"] = dict(execution.rejection_codes)
        return counts

    def snapshot_scan(self, scan_id: str):
        """Record what this scan saw as an :class:`AssetSnapshot`.

        ``complete`` is true only when every task settled successfully — a scan
        with failed, blocked, or quarantined work is partial coverage, and a
        partial snapshot may never justify calling an asset removed.
        """
        tasks = self._repo.tasks_for_scan(scan_id)
        complete = bool(tasks) and all(t.status == scans.TaskState.SUCCEEDED.value for t in tasks)
        seen = {o.asset_key for o in self._repo.observations_for_scan(scan_id)}
        assets = [
            a for a in self._repo.assets_for_engagement(self._config.engagement_id)
            if a.asset_key in seen
        ]
        snapshot = new_snapshot(
            engagement_id=self._config.engagement_id, scan_id=scan_id,
            assets=assets, complete=complete,
        )
        self._repo.save_snapshot(snapshot)
        self._count("snapshot_coverage", coverage="complete" if complete else "partial")
        return snapshot

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
    assets: dict = field(default_factory=dict)
    rejections: int = 0
    rejection_codes: dict = field(default_factory=dict)
    sensitive: bool = False
    sensitive_classifications: list = field(default_factory=list)


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
        for dep in (*by_key[key].depends_on, *by_key[key].stream_from):
            if dep not in by_key:
                raise ValueError(f"stage {key!r} depends on unknown stage {dep!r}")
            visit(dep)
        visiting.discard(key)
        seen.add(key)
        ordered.append(by_key[key])

    for spec in stages:
        visit(spec.key)
    return ordered
