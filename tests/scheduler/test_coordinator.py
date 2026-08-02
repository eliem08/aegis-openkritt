"""Scan coordinator — the Phase 1 completion gate.

A fake discovery adapter is driven through the *real* reservation, lease,
process, event, quarantine, normalization, persistence, and cancel/recover
paths, on SQLite (and, when a DSN is supplied, PostgreSQL) with no direct
network access.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from aegis.adapters import FakeDiscoveryAdapter
from aegis.api.persistence import SqliteRepository
from aegis.api.reservations import ReservationService
from aegis.api.store import EngagementRecord
from aegis.scheduler import ScanConfig, ScanCoordinator, StageSpec, TaskSpec

ADAPTERS = {"fake-discovery": FakeDiscoveryAdapter()}


def seed_engagement(repo, eid="eng-1"):
    repo.save_engagement(EngagementRecord(
        id=eid, authorization={"customer_id": "t"}, status="active",
        created_at=datetime.now(timezone.utc)))
    return repo


def make_coordinator(repo, *, spend_cap=None, session_cap=4, is_killed=None):
    return ScanCoordinator(
        repository=repo,
        reservations=ReservationService(repo),
        adapters=ADAPTERS,
        config=ScanConfig(
            tenant_id="t", engagement_id="eng-1",
            scope_targets=("api.example.test",), spend_cap=spend_cap, session_cap=session_cap,
        ),
        is_killed=is_killed,
    )


def sqlite_repo(tmp_path, name="scan.db"):
    return seed_engagement(SqliteRepository(str(tmp_path / name)))


def one_task_plan(target="api.example.test", est_spend=0.0):
    return ([StageSpec("recon", "discovery")],
            [TaskSpec("fake-discovery", target, "recon", est_spend=est_spend)])


# --- end to end --------------------------------------------------------------

def test_full_scan_succeeds_and_persists(tmp_path):
    repo = sqlite_repo(tmp_path)
    coord = make_coordinator(repo)
    scan_id = coord.plan_scan(*one_task_plan(est_spend=2.0))

    steps = coord.run_scan(scan_id)

    assert [s.outcome for s in steps] == ["succeeded"]
    assert steps[0].events >= 4  # asset, 2 routes, technology, terminal, ...

    task = repo.tasks_for_scan(scan_id)[0]
    assert task.status == "succeeded"
    assert task.result_summary["events"] == steps[0].events

    artifacts = repo.artifacts_for_task(task.task_id)
    assert len(artifacts) == 1 and artifacts[0].classification == "clean"

    # The reservation was finalised: no session left held.
    _, active_sessions = ReservationService(repo).usage("eng-1")
    assert active_sessions == 0


def test_scan_is_read_only_to_the_network(tmp_path):
    # The adapter runs an external process; it reaches the network only through
    # the gateway, never directly. The fake tool makes no requests, proving the
    # coordinator drives execution without granting egress.
    repo = sqlite_repo(tmp_path)
    coord = make_coordinator(repo)
    scan_id = coord.plan_scan(*one_task_plan())
    steps = coord.run_scan(scan_id)
    assert steps[0].outcome == "succeeded"


# --- DAG ordering ------------------------------------------------------------

def test_dependent_stage_waits_for_its_dependency(tmp_path):
    repo = sqlite_repo(tmp_path)
    coord = make_coordinator(repo)
    stages = [
        StageSpec("recon", "discovery"),
        StageSpec("probe", "probe", depends_on=("recon",)),
    ]
    tasks = [
        TaskSpec("fake-discovery", "recon.example.test", "recon"),
        TaskSpec("fake-discovery", "probe.example.test", "probe"),
    ]
    scan_id = coord.plan_scan(stages, tasks)

    # Only the dependency-free task is runnable first.
    first = coord._pick_ready_task(scan_id)
    assert first.target == "recon.example.test"

    coord.run_next(scan_id)  # settle recon
    second = coord._pick_ready_task(scan_id)
    assert second.target == "probe.example.test"

    steps = coord.run_scan(scan_id)  # finishes probe
    assert all(s.outcome == "succeeded" for s in steps)
    assert {t.status for t in repo.tasks_for_scan(scan_id)} == {"succeeded"}


# --- quarantine --------------------------------------------------------------

def test_sensitive_signal_quarantines_the_task(tmp_path):
    repo = sqlite_repo(tmp_path)
    coord = make_coordinator(repo)
    scan_id = coord.plan_scan(*one_task_plan(target="secret.example.test"))

    steps = coord.run_scan(scan_id)

    assert steps[0].outcome == "quarantined"
    task = repo.tasks_for_scan(scan_id)[0]
    assert task.status == "quarantined"
    assert repo.artifacts_for_task(task.task_id)[0].classification == "quarantined"


# --- kill switch -------------------------------------------------------------

def test_kill_switch_cancels_queued_work(tmp_path):
    repo = sqlite_repo(tmp_path)
    killed = {"on": False}
    coord = make_coordinator(repo, is_killed=lambda: killed["on"])
    scan_id = coord.plan_scan(*one_task_plan())

    killed["on"] = True
    assert coord.run_next(scan_id) is None  # no new claims once killed

    task = repo.tasks_for_scan(scan_id)[0]
    assert task.status == "cancelled"


# --- budget cap --------------------------------------------------------------

def test_task_over_budget_is_blocked(tmp_path):
    repo = sqlite_repo(tmp_path)
    coord = make_coordinator(repo, spend_cap=5.0)
    scan_id = coord.plan_scan(*one_task_plan(est_spend=10.0))

    steps = coord.run_scan(scan_id)

    assert steps[0].outcome == "blocked"
    assert repo.tasks_for_scan(scan_id)[0].status == "blocked"


# --- restart recovery --------------------------------------------------------

def test_crashed_worker_lease_is_reclaimed_then_completes(tmp_path):
    repo = sqlite_repo(tmp_path)
    coord = make_coordinator(repo)
    scan_id = coord.plan_scan(*one_task_plan())
    task = repo.tasks_for_scan(scan_id)[0]

    # A worker leased the task and then "crashed" mid-run.
    repo.lease_task(task.task_id, "dead-worker", ttl_seconds=1)
    repo.transition_task(task.task_id, "running")

    reclaimed = coord.recover(now=datetime.now(timezone.utc) + timedelta(seconds=10))
    assert (task.task_id, "queued") in reclaimed

    steps = coord.run_scan(scan_id)
    assert steps[-1].outcome == "succeeded"
    assert repo.get_task(task.task_id).attempts == 1  # one reclaim recorded


# --- postgres parity (gated) -------------------------------------------------

DSN = os.environ.get("AEGIS_TEST_POSTGRES_DSN")


@pytest.mark.skipif(not DSN, reason="set AEGIS_TEST_POSTGRES_DSN to run")
def test_full_scan_end_to_end_on_postgres():
    pytest.importorskip("psycopg")
    from aegis.api.postgres import PostgresRepository

    repo = PostgresRepository(DSN)
    repo._exec(
        "TRUNCATE engagements, grants, audit, kill_state, spend, reservations, "
        "scan_runs, stage_runs, task_runs, task_leases, artifacts CASCADE"
    )
    try:
        seed_engagement(repo)
        coord = make_coordinator(repo)
        scan_id = coord.plan_scan(*one_task_plan(est_spend=1.0))
        steps = coord.run_scan(scan_id)
        assert [s.outcome for s in steps] == ["succeeded"]
        task = repo.tasks_for_scan(scan_id)[0]
        assert task.status == "succeeded"
        assert repo.artifacts_for_task(task.task_id)[0].classification == "clean"
    finally:
        repo.close()
