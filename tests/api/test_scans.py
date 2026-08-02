"""Durable scan model: idempotency, compare-and-set leasing, state machine, and
restart recovery (reclaim expired leases; preserve completed work)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aegis.api.persistence import SqliteRepository
from aegis.api.scans import InvalidTaskTransition, new_scan, new_stage, new_task
from aegis.api.store import EngagementRecord


def repo_with_engagement(tmp_path, eid="eng-1") -> SqliteRepository:
    repo = SqliteRepository(str(tmp_path / "s.db"))
    repo.save_engagement(EngagementRecord(
        id=eid, authorization={"customer_id": "t"}, status="active", created_at=datetime.now(timezone.utc)))
    return repo


def _scan_stage(repo, eid="eng-1"):
    scan = new_scan(tenant_id="t", engagement_id=eid)
    repo.create_scan(scan)
    stage = new_stage(scan_id=scan.scan_id, stage_type="probe")
    repo.create_stage(stage)
    return scan, stage


def test_create_and_get_roundtrip(tmp_path):
    repo = repo_with_engagement(tmp_path)
    scan, stage = _scan_stage(repo)
    task = new_task(scan_id=scan.scan_id, stage_id=stage.stage_id, target="a", adapter="fake",
                    adapter_version="1", input_hash="h")
    repo.create_task(task)
    assert repo.get_scan(scan.scan_id).engagement_id == "eng-1"
    got = repo.get_task(task.task_id)
    assert got.status == "queued" and got.adapter == "fake"


def test_create_task_is_idempotent(tmp_path):
    repo = repo_with_engagement(tmp_path)
    scan, stage = _scan_stage(repo)
    kw = dict(scan_id=scan.scan_id, stage_id=stage.stage_id, target="a", adapter="f",
              adapter_version="1", input_hash="h")
    a = repo.create_task(new_task(**kw))
    b = repo.create_task(new_task(**kw))  # same idempotency key
    assert b.task_id == a.task_id
    assert len(repo.tasks_for_scan(scan.scan_id)) == 1


def test_lease_is_compare_and_set(tmp_path):
    repo = repo_with_engagement(tmp_path)
    scan, stage = _scan_stage(repo)
    t = repo.create_task(new_task(scan_id=scan.scan_id, stage_id=stage.stage_id, target="a",
                                  adapter="f", adapter_version="1", input_hash="h"))
    assert repo.lease_task(t.task_id, "w1", ttl_seconds=300) is not None
    assert repo.lease_task(t.task_id, "w2", ttl_seconds=300) is None  # already leased
    assert repo.get_task(t.task_id).status == "leased"


def test_heartbeat_extends_lease(tmp_path):
    repo = repo_with_engagement(tmp_path)
    scan, stage = _scan_stage(repo)
    t = repo.create_task(new_task(scan_id=scan.scan_id, stage_id=stage.stage_id, target="a",
                                  adapter="f", adapter_version="1", input_hash="h"))
    lease = repo.lease_task(t.task_id, "w1", ttl_seconds=1)
    assert repo.heartbeat(lease.lease_id, ttl_seconds=300) is True
    assert repo.heartbeat("no-such-lease") is False


def test_invalid_transition_fails_closed(tmp_path):
    repo = repo_with_engagement(tmp_path)
    scan, stage = _scan_stage(repo)
    t = repo.create_task(new_task(scan_id=scan.scan_id, stage_id=stage.stage_id, target="a",
                                  adapter="f", adapter_version="1", input_hash="h"))
    with pytest.raises(InvalidTaskTransition):
        repo.transition_task(t.task_id, "succeeded")  # queued -> succeeded is invalid
    assert repo.get_task(t.task_id).status == "queued"  # unchanged


def test_valid_transition_path(tmp_path):
    repo = repo_with_engagement(tmp_path)
    scan, stage = _scan_stage(repo)
    t = repo.create_task(new_task(scan_id=scan.scan_id, stage_id=stage.stage_id, target="a",
                                  adapter="f", adapter_version="1", input_hash="h"))
    repo.lease_task(t.task_id, "w1")
    repo.transition_task(t.task_id, "running")
    done = repo.transition_task(t.task_id, "succeeded", result_summary={"ok": True})
    assert done.status == "succeeded" and done.result_summary == {"ok": True}
    assert repo.artifacts_for_task(t.task_id) == []  # lease released on success


def test_restart_recovery_reclaims_and_preserves_completed(tmp_path):
    repo = repo_with_engagement(tmp_path)
    scan, stage = _scan_stage(repo)
    t1 = repo.create_task(new_task(scan_id=scan.scan_id, stage_id=stage.stage_id, target="a",
                                   adapter="f", adapter_version="1", input_hash="h1"))
    t2 = repo.create_task(new_task(scan_id=scan.scan_id, stage_id=stage.stage_id, target="b",
                                   adapter="f", adapter_version="1", input_hash="h2"))
    repo.lease_task(t1.task_id, "worker-1", ttl_seconds=1)  # will expire
    repo.lease_task(t2.task_id, "worker-2", ttl_seconds=300)
    repo.transition_task(t2.task_id, "running")
    repo.transition_task(t2.task_id, "succeeded")  # completed work

    future = datetime.now(timezone.utc) + timedelta(seconds=60)
    reclaimed = {tid: st for tid, st in repo.reclaim_expired_leases(now=future)}

    assert reclaimed.get(t1.task_id) == "queued"       # requeued
    assert t2.task_id not in reclaimed                  # succeeded, untouched
    assert repo.get_task(t1.task_id).status == "queued"
    assert repo.get_task(t1.task_id).attempts == 1
    assert repo.get_task(t2.task_id).status == "succeeded"
    assert repo.lease_task(t1.task_id, "worker-3") is not None  # re-leasable


def test_non_retryable_task_is_blocked_on_reclaim(tmp_path):
    repo = repo_with_engagement(tmp_path)
    scan, stage = _scan_stage(repo)
    t = repo.create_task(new_task(scan_id=scan.scan_id, stage_id=stage.stage_id, target="a",
                                  adapter="f", adapter_version="1", input_hash="h", retryable=False))
    repo.lease_task(t.task_id, "w", ttl_seconds=1)
    future = datetime.now(timezone.utc) + timedelta(seconds=60)
    repo.reclaim_expired_leases(now=future)
    assert repo.get_task(t.task_id).status == "blocked"  # state-changing work is not auto-retried


def test_foreign_key_rejects_orphan_scan(tmp_path):
    repo = SqliteRepository(str(tmp_path / "fk.db"))  # no engagement
    scan = new_scan(tenant_id="t", engagement_id="ghost")
    with pytest.raises(Exception):
        repo.create_scan(scan)  # FK to engagements(id) is enforced
