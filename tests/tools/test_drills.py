"""Phase 5 failure drills that ARE runnable in-process (executed, not simulated).

These convert previously-"blocked" drills into real, CI-covered checks: a Redis
outage fails closed and reconciles on recovery; concurrent load cannot overbook a
reservation cap; and the kill switch drains in-flight work.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from types import SimpleNamespace

from aegis.adapters import FakeDiscoveryAdapter
from aegis.api.persistence import SqliteRepository
from aegis.api.reservations import ReservationService
from aegis.api.store import EngagementRecord
from aegis.coord import Admission, Coordinator, InMemoryBackend
from aegis.scheduler import ScanConfig, ScanCoordinator, StageSpec, TaskSpec

NOW = datetime(2026, 8, 3, tzinfo=timezone.utc)


# --- Drill: Redis outage fails closed, recovers, reconciles ------------------

def test_drill_redis_outage_fails_closed_and_reconciles():
    backend = InMemoryBackend()
    coord = Coordinator(backend)

    # healthy: active work admitted, a slot acquired
    assert coord.admit("authenticated_testing") is Admission.ADMIT
    assert coord.acquire("sem", 5, "w1") and coord.acquire("sem", 5, "w2")

    # outage: new active work is denied, passive may pause, cancellation assumed
    backend.connected = False
    assert coord.admit("authenticated_testing") is Admission.DENY
    assert coord.admit("passive_discovery") is Admission.PAUSE
    assert coord.rate_allow("k", 100, 10) is False
    assert coord.acquire("sem", 100, "w3") is False
    assert coord.is_cancelled("scan:1") is True            # cannot disprove a kill

    # recovery: rebuild the semaphore from the durable PG leases (w1, w2 hold tasks)
    backend.connected = True
    assert coord.reconcile("sem", ["w1", "w2"]) == {"w1", "w2"}
    assert coord.held("sem") == 2


# --- Drill: concurrent load cannot overbook a cap ----------------------------

def test_drill_load_does_not_overbook_under_concurrency(tmp_path):
    repo = SqliteRepository(str(tmp_path / "load.db"))
    svc = ReservationService(repo)
    eng = SimpleNamespace(id="e1", authorization=SimpleNamespace(
        spend_budget=None, rate_limits=SimpleNamespace(max_concurrent_sessions=10)))

    winners: list = []
    lock = threading.Lock()

    def worker(i):
        r = svc.reserve(eng, sessions=1, idempotency_key=f"k{i}")
        with lock:
            winners.append(r)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(80)]
    start = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.perf_counter() - start

    granted = [r for r in winners if r is not None]
    assert len(granted) == 10                              # exactly the cap, never more
    assert svc.usage("e1")[1] == 10
    assert elapsed < 30                                    # completed under load


# --- Drill: kill switch drains in-flight work --------------------------------

def test_drill_kill_switch_drains_in_flight_scan(tmp_path):
    repo = SqliteRepository(str(tmp_path / "kill.db"))
    repo.save_engagement(EngagementRecord(id="eng-1", authorization={"customer_id": "t"},
                                          status="active", created_at=NOW))
    killed = {"on": False}
    coord = ScanCoordinator(
        repository=repo, reservations=ReservationService(repo),
        adapters={"fake-discovery": FakeDiscoveryAdapter()},
        config=ScanConfig(tenant_id="t", engagement_id="eng-1",
                          scope_targets=("api.example.test",)),
        is_killed=lambda: killed["on"])

    scan_id = coord.plan_scan(
        [StageSpec("recon", "discovery")],
        [TaskSpec("fake-discovery", "api.example.test", "recon"),
         TaskSpec("fake-discovery", "api.example.test", "recon", input_hash="b"),
         TaskSpec("fake-discovery", "api.example.test", "recon", input_hash="c")])

    coord.run_next(scan_id)                                # one task runs
    killed["on"] = True                                    # kill fires mid-scan
    assert coord.run_next(scan_id) is None                 # no new claims

    statuses = [t.status for t in repo.tasks_for_scan(scan_id)]
    assert "cancelled" in statuses                         # queued work drained
    # nothing succeeded after the kill beyond the single pre-kill task
    assert statuses.count("succeeded") <= 1
