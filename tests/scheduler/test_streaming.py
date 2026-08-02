"""Streaming stage handoff (Phase 2 §Stage graph).

A downstream stage may start from validated incremental events while its producer
is still running, but **task completion is recorded separately from partial
progress** — and a task that ends up quarantined never contributes to the asset
graph, even though its events streamed.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from aegis.adapters import FakeDiscoveryAdapter
from aegis.api import graph_serde
from aegis.api.persistence import SqliteRepository
from aegis.api.reservations import ReservationService
from aegis.api.store import EngagementRecord
from aegis.scheduler import ScanConfig, ScanCoordinator, StageSpec, TaskSpec

TARGETS = ("api.example.test", "secret.example.test")


def repo(tmp_path, name="stream.db"):
    r = SqliteRepository(str(tmp_path / name))
    r.save_engagement(EngagementRecord(
        id="eng-1", authorization={"customer_id": "t"}, status="active",
        created_at=datetime.now(timezone.utc)))
    return r


def coordinator(repository, targets=TARGETS):
    return ScanCoordinator(
        repository=repository, reservations=ReservationService(repository),
        adapters={"fake-discovery": FakeDiscoveryAdapter()},
        config=ScanConfig(tenant_id="t", engagement_id="eng-1", scope_targets=tuple(targets)),
    )


def streaming_plan(target="api.example.test"):
    """A producer stage plus a consumer that streams from it."""
    return (
        [StageSpec("recon", "discovery"),
         StageSpec("probe", "probe", stream_from=("recon",), min_stream_events=1)],
        [TaskSpec("fake-discovery", target, "recon"),
         TaskSpec("fake-discovery", target, "probe", input_hash="probe")],
    )


# --- progress is recorded separately from completion --------------------------

def test_progress_is_recorded_while_the_task_is_still_running(tmp_path):
    r = repo(tmp_path)
    coord = coordinator(r)
    scan_id = coord.plan_scan(*streaming_plan())
    producer = r.tasks_for_scan(scan_id)[0]

    seen = []

    # Capture what progress looked like from *outside* the task, mid-run.
    original = r.record_progress

    def spy(task_id, scan_id_, **kw):
        original(task_id, scan_id_, **kw)
        task = r.get_task(task_id)
        seen.append((kw.get("events", 0), task.status))

    r.record_progress = spy
    coord.run_next(scan_id)
    r.record_progress = original

    assert seen, "expected incremental progress while running"
    # Progress climbed while the task was still 'running' — never 'succeeded'.
    assert [events for events, _ in seen] == sorted(events for events, _ in seen)
    assert all(status == "running" for _, status in seen)
    # Completion is a separate record, written only at the end.
    assert r.get_task(producer.task_id).status == "succeeded"
    assert r.get_progress(producer.task_id).events > 0


def test_progress_survives_as_its_own_record(tmp_path):
    r = repo(tmp_path)
    coord = coordinator(r)
    scan_id = coord.plan_scan(*streaming_plan())
    coord.run_next(scan_id)

    progress = [p for p in r.progress_for_scan(scan_id) if p]
    assert progress and progress[0].events > 0
    assert progress[0].scan_id == scan_id and progress[0].stage_id


# --- downstream starts from partial progress ---------------------------------

def test_streaming_consumer_starts_before_its_producer_settles(tmp_path):
    r = repo(tmp_path)
    coord = coordinator(r)
    scan_id = coord.plan_scan(*streaming_plan())
    producer = r.tasks_for_scan(scan_id)[0]

    # Producer leased and running, with some validated events already streamed.
    r.lease_task(producer.task_id, "w1")
    r.transition_task(producer.task_id, "running")
    r.record_progress(producer.task_id, scan_id, stage_id=producer.stage_id, events=3)

    ready = coord._pick_ready_task(scan_id)
    assert ready is not None and ready.task_id != producer.task_id  # the consumer may start
    assert r.get_task(producer.task_id).status == "running"          # producer not settled


def test_consumer_waits_until_the_stream_has_enough_events(tmp_path):
    r = repo(tmp_path)
    coord = coordinator(r)
    stages = [StageSpec("recon", "discovery"),
              StageSpec("probe", "probe", stream_from=("recon",), min_stream_events=5)]
    tasks = [TaskSpec("fake-discovery", "api.example.test", "recon"),
             TaskSpec("fake-discovery", "api.example.test", "probe", input_hash="probe")]
    scan_id = coord.plan_scan(stages, tasks)
    producer = r.tasks_for_scan(scan_id)[0]

    r.lease_task(producer.task_id, "w1")
    r.transition_task(producer.task_id, "running")
    r.record_progress(producer.task_id, scan_id, stage_id=producer.stage_id, events=2)
    assert coord._pick_ready_task(scan_id) is None    # 2 < 5: not enough yet

    r.record_progress(producer.task_id, scan_id, stage_id=producer.stage_id, events=5)
    assert coord._pick_ready_task(scan_id) is not None


def test_blocking_dependency_still_waits_for_completion(tmp_path):
    r = repo(tmp_path)
    coord = coordinator(r)
    stages = [StageSpec("recon", "discovery"),
              StageSpec("probe", "probe", depends_on=("recon",))]   # blocking, not streaming
    tasks = [TaskSpec("fake-discovery", "api.example.test", "recon"),
             TaskSpec("fake-discovery", "api.example.test", "probe", input_hash="probe")]
    scan_id = coord.plan_scan(stages, tasks)
    producer = r.tasks_for_scan(scan_id)[0]

    r.lease_task(producer.task_id, "w1")
    r.transition_task(producer.task_id, "running")
    r.record_progress(producer.task_id, scan_id, stage_id=producer.stage_id, events=99)
    assert coord._pick_ready_task(scan_id) is None    # progress is irrelevant here


def test_a_streaming_scan_runs_to_completion(tmp_path):
    r = repo(tmp_path)
    coord = coordinator(r)
    scan_id = coord.plan_scan(*streaming_plan())
    steps = coord.run_scan(scan_id)
    assert [s.outcome for s in steps] == ["succeeded", "succeeded"]
    assert coord.snapshot_scan(scan_id).complete is True


# --- provisional vs promoted --------------------------------------------------

def test_streamed_observations_are_promoted_only_on_clean_completion(tmp_path):
    r = repo(tmp_path)
    coord = coordinator(r)
    scan_id = coord.plan_scan(
        [StageSpec("recon", "discovery")],
        [TaskSpec("fake-discovery", "api.example.test", "recon")],
    )
    step = coord.run_scan(scan_id)[0]
    assert step.outcome == "succeeded"

    task = r.tasks_for_scan(scan_id)[0]
    assert set(r.observation_state_counts(task.task_id)) == {graph_serde.PROMOTED}
    assert r.observations_for_scan(scan_id)            # visible to the graph
    assert r.assets_for_engagement("eng-1")


def test_quarantined_stream_is_never_promoted_into_the_graph(tmp_path):
    r = repo(tmp_path)
    coord = coordinator(r)
    scan_id = coord.plan_scan(
        [StageSpec("recon", "discovery")],
        [TaskSpec("fake-discovery", "secret.example.test", "recon")],
    )
    step = coord.run_scan(scan_id)[0]
    assert step.outcome == "quarantined"

    task = r.tasks_for_scan(scan_id)[0]
    # Its events did stream and were written provisionally...
    streamed = r.observations_for_task(task.task_id)
    assert streamed, "events should have streamed before quarantine"
    assert set(r.observation_state_counts(task.task_id)) == {graph_serde.QUARANTINED}
    # ...but the asset graph never sees them.
    assert r.observations_for_scan(scan_id) == []
    assert r.assets_for_engagement("eng-1") == []
    assert coord.snapshot_scan(scan_id).entries == {}


@pytest.mark.parametrize("states,expected_visible", [
    ((graph_serde.PROMOTED,), False),
    (None, True),
])
def test_provisional_rows_are_hidden_from_the_graph_view(tmp_path, states, expected_visible):
    r = repo(tmp_path)
    coord = coordinator(r)
    scan_id = coord.plan_scan(
        [StageSpec("recon", "discovery")],
        [TaskSpec("fake-discovery", "api.example.test", "recon")],
    )
    task = r.tasks_for_scan(scan_id)[0]
    # Simulate a task mid-stream: provisional rows exist, nothing promoted yet.
    from aegis.graph import AssetKind, new_observation

    obs = new_observation(
        engagement_id="eng-1", scan_id=scan_id, task_id=task.task_id,
        asset_key="domain:api.example.test", kind=AssetKind.DOMAIN,
        source="fake-discovery", data={"identifier": "api.example.test"},
    )
    r.record_observations([obs], graph_serde.PROVISIONAL)
    assert bool(r.observations_for_task(task.task_id, states=states)) is expected_visible
    assert r.observations_for_scan(scan_id) == []   # graph view stays clean
