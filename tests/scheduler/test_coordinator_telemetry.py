"""Coordinator emits telemetry on the task hot path (Phase 5 wiring)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from aegis.adapters import FakeDiscoveryAdapter
from aegis.api.persistence import SqliteRepository
from aegis.api.reservations import ReservationService
from aegis.api.store import EngagementRecord
from aegis.observ import MetricNames, Telemetry
from aegis.scheduler import ScanConfig, ScanCoordinator, StageSpec, TaskSpec

NOW = datetime(2026, 8, 2, tzinfo=timezone.utc)
TARGETS = ("api.example.test", "leak.example.test")


def repo(tmp_path):
    r = SqliteRepository(str(tmp_path / "tel.db"))
    r.save_engagement(EngagementRecord(id="eng-1", authorization={"customer_id": "t"},
                                       status="active", created_at=NOW))
    return r


def coordinator(r, tel, targets=TARGETS):
    return ScanCoordinator(
        repository=r, reservations=ReservationService(r),
        adapters={"fake-discovery": FakeDiscoveryAdapter()},
        config=ScanConfig(tenant_id="tenant-a", engagement_id="eng-1", scope_targets=tuple(targets)),
        telemetry=tel)


def plan(coord, target="api.example.test"):
    return coord.plan_scan([StageSpec("recon", "discovery")],
                           [TaskSpec("fake-discovery", target, "recon")])


def names(tel):
    return {m.name for m in tel.exporter.metrics}


def test_task_run_emits_a_span_with_pseudonymous_tenant(tmp_path):
    tel = Telemetry()
    coord = coordinator(repo(tmp_path), tel)
    coord.run_scan(plan(coord))
    spans = [s for s in tel.exporter.spans if s.name == "scan.task.run"]
    assert spans and spans[0].attributes["adapter"] == "fake-discovery"
    assert spans[0].attributes["tenant_id"].startswith("tnt_")   # never the raw id


def test_reservation_latency_is_recorded(tmp_path):
    tel = Telemetry()
    coord = coordinator(repo(tmp_path), tel)
    coord.run_scan(plan(coord))
    assert MetricNames.RESERVATION_LATENCY in names(tel)


def test_sensitive_quarantine_is_counted(tmp_path):
    tel = Telemetry()
    coord = coordinator(repo(tmp_path), tel)
    coord.run_scan(plan(coord, target="leak.example.test"))
    quarantines = [m for m in tel.exporter.metrics if m.name == MetricNames.SENSITIVE_QUARANTINES]
    assert quarantines and quarantines[0].labels["category"] == "credential"


def test_snapshot_coverage_is_recorded(tmp_path):
    tel = Telemetry()
    r = repo(tmp_path)
    coord = coordinator(r, tel)
    scan_id = plan(coord)
    coord.run_scan(scan_id)
    coord.snapshot_scan(scan_id)
    coverage = [m for m in tel.exporter.metrics if m.name == MetricNames.SNAPSHOT_COVERAGE]
    assert coverage and coverage[0].labels["coverage"] == "complete"


def test_lease_expiry_is_counted_on_recover(tmp_path):
    tel = Telemetry()
    r = repo(tmp_path)
    coord = coordinator(r, tel)
    scan_id = plan(coord)
    task = r.tasks_for_scan(scan_id)[0]
    r.lease_task(task.task_id, "dead", ttl_seconds=-5)
    r.transition_task(task.task_id, "running")
    coord.recover(now=datetime.now(timezone.utc) + timedelta(seconds=10))
    assert MetricNames.LEASE_EXPIRY in names(tel)


def test_no_telemetry_still_runs(tmp_path):
    r = repo(tmp_path)
    coord = ScanCoordinator(
        repository=r, reservations=ReservationService(r),
        adapters={"fake-discovery": FakeDiscoveryAdapter()},
        config=ScanConfig(tenant_id="t", engagement_id="eng-1", scope_targets=("api.example.test",)))
    assert coord.run_scan(plan(coord))[0].outcome == "succeeded"   # no telemetry -> no error
