"""Distributed coordination (Phase 5) — primitives + fail-closed on backend loss."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from aegis.coord import Admission, Coordinator, InMemoryBackend


class Clock:
    def __init__(self):
        self.now = datetime(2026, 8, 2, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, s):
        self.now += timedelta(seconds=s)


def coord(clock=None, **kw):
    return Coordinator(InMemoryBackend(clock=clock), **kw), clock


# --- rate buckets ------------------------------------------------------------

def test_rate_bucket_allows_up_to_limit_then_denies():
    clock = Clock()
    c, _ = coord(clock)
    allowed = [c.rate_allow("t:api", limit=3, window_seconds=10) for _ in range(5)]
    assert allowed == [True, True, True, False, False]


def test_rate_bucket_resets_after_the_window():
    clock = Clock()
    c, _ = coord(clock)
    for _ in range(3):
        c.rate_allow("k", 3, 10)
    assert c.rate_allow("k", 3, 10) is False
    clock.advance(11)
    assert c.rate_allow("k", 3, 10) is True


# --- semaphores --------------------------------------------------------------

def test_semaphore_bounds_concurrency():
    c, _ = coord()
    assert c.acquire("sem", 2, "w1") and c.acquire("sem", 2, "w2")
    assert c.acquire("sem", 2, "w3") is False       # full
    c.release("sem", "w1")
    assert c.acquire("sem", 2, "w3") is True         # slot freed


def test_semaphore_acquire_is_idempotent():
    c, _ = coord()
    assert c.acquire("sem", 1, "w1") and c.acquire("sem", 1, "w1")   # same holder ok
    assert c.held("sem") == 1


def test_semaphore_members_expire():
    clock = Clock()
    c, _ = coord(clock)
    c.acquire("sem", 1, "w1", ttl_seconds=5)
    clock.advance(6)
    assert c.acquire("sem", 1, "w2") is True         # w1's slot expired


# --- cancellation + dedup ----------------------------------------------------

def test_cancellation_broadcast_is_visible():
    c, _ = coord()
    assert not c.is_cancelled("scan:1")
    c.broadcast_cancel("scan:1")
    assert c.is_cancelled("scan:1") and not c.is_cancelled("scan:2")


def test_dedup_marks_first_sighting_only():
    c, _ = coord()
    assert c.is_duplicate("evt:1") is False          # first time
    assert c.is_duplicate("evt:1") is True           # already seen


# --- fail closed on backend loss --------------------------------------------

def test_active_work_is_denied_when_the_backend_is_down():
    backend = InMemoryBackend()
    c = Coordinator(backend)
    backend.connected = False
    assert c.admit("authenticated_testing") == Admission.DENY
    assert c.admit("template_scan") == Admission.DENY
    assert c.rate_allow("k", 100, 10) is False       # fail closed
    assert c.acquire("sem", 100, "w1") is False


def test_passive_work_may_pause_when_the_backend_is_down():
    backend = InMemoryBackend()
    c = Coordinator(backend, pause_passive_on_loss=True)
    backend.connected = False
    assert c.admit("passive_discovery") == Admission.PAUSE


def test_passive_work_fails_closed_when_pause_is_disabled():
    backend = InMemoryBackend()
    c = Coordinator(backend, pause_passive_on_loss=False)
    backend.connected = False
    assert c.admit("passive_discovery") == Admission.DENY


def test_cancellation_is_assumed_when_the_backend_is_down():
    backend = InMemoryBackend()
    c = Coordinator(backend)
    backend.connected = False
    assert c.is_cancelled("scan:1") is True          # cannot disprove a kill -> stop


# --- reconciliation ----------------------------------------------------------

def test_reconcile_rebuilds_the_semaphore_from_durable_leases():
    backend = InMemoryBackend()
    c = Coordinator(backend)
    c.acquire("sem", 5, "stale-worker")              # ephemeral holder with no durable lease

    # after a "Redis loss", durable PG leases are the truth: w1, w2 hold tasks
    restored = c.reconcile("sem", ["w1", "w2"])
    assert restored == {"w1", "w2"}                  # stale holder dropped, durable ones present
    assert c.held("sem") == 2
