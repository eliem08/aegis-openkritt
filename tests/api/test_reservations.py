"""Atomic reservations: no overbooking under concurrency; idempotent finalize."""

from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from aegis.api.persistence import SqliteRepository
from aegis.api.reservations import ReservationError, ReservationService


def eng(spend_budget=100.0, sessions=10_000, eid="e1"):
    return SimpleNamespace(
        id=eid,
        authorization=SimpleNamespace(
            spend_budget=spend_budget,
            rate_limits=SimpleNamespace(max_concurrent_sessions=sessions),
        ),
    )


def svc(tmp_path, name="r.db") -> ReservationService:
    return ReservationService(SqliteRepository(str(tmp_path / name)))


def test_no_overbooking_under_concurrency(tmp_path):
    s = svc(tmp_path)
    e = eng(spend_budget=100.0)
    results: list = []
    lock = threading.Lock()

    def worker(i):
        r = s.reserve(e, spend=10.0, sessions=1, idempotency_key=f"k{i}")
        with lock:
            results.append(r)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    ok = [r for r in results if r is not None]
    assert len(ok) == 10  # exactly 100 / 10, never more
    assert s.usage("e1")[0] == 100.0


def test_session_slots_capped_and_freed_on_finalize(tmp_path):
    s = svc(tmp_path)
    e = eng(spend_budget=None, sessions=3)  # unlimited spend, 3 concurrent slots
    r1 = s.reserve(e, spend=0, sessions=1, idempotency_key="a")
    s.reserve(e, spend=0, sessions=1, idempotency_key="b")
    s.reserve(e, spend=0, sessions=1, idempotency_key="c")
    assert s.reserve(e, spend=0, sessions=1, idempotency_key="d") is None  # 4th blocked
    s.finalize(r1.reservation_id)  # frees a slot
    assert s.reserve(e, spend=0, sessions=1, idempotency_key="d") is not None


def test_idempotent_reserve_charges_once(tmp_path):
    s = svc(tmp_path)
    e = eng()
    a = s.reserve(e, spend=10, idempotency_key="k")
    b = s.reserve(e, spend=10, idempotency_key="k")
    assert a.reservation_id == b.reservation_id
    assert s.usage("e1")[0] == 10.0  # not double-charged


def test_finalize_records_actual_and_releases_remainder(tmp_path):
    s = svc(tmp_path)
    e = eng()
    r = s.reserve(e, spend=10, idempotency_key="k")
    s.finalize(r.reservation_id, 7.0)
    again = s.finalize(r.reservation_id, 999.0)  # idempotent: second finalize ignored
    assert again.spend_final == 7.0
    assert s.usage("e1")[0] == 7.0  # unused 3.0 released


def test_release_frees_reservation(tmp_path):
    s = svc(tmp_path)
    e = eng()
    r = s.reserve(e, spend=10, idempotency_key="k")
    assert s.usage("e1")[0] == 10.0
    s.release(r.reservation_id)
    assert s.usage("e1")[0] == 0.0


def test_reserve_rejects_negative(tmp_path):
    s = svc(tmp_path)
    with pytest.raises(ReservationError):
        s.reserve(eng(), spend=-1, idempotency_key="k")


def test_service_requires_repository():
    with pytest.raises(ReservationError):
        ReservationService(None)


def test_unlimited_spend_budget(tmp_path):
    s = svc(tmp_path)
    e = eng(spend_budget=None)
    assert s.reserve(e, spend=1_000_000, idempotency_key="k") is not None
