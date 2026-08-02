"""Single-use approvals are consumed *atomically with a reservation* — the final
Phase 1 gate item. Two concurrent reservations can never both burn one token, and
a failed reservation never burns it."""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from aegis.api.persistence import SqliteRepository
from aegis.api.reservations import ReservationService
from aegis.api.store import ApprovalGrant, _safe_host

ACTION, TARGET = "safe_state_change", "api.example.test"
APPROVAL = (ACTION, TARGET)


def eng(spend_budget=100.0, sessions=10_000, eid="e1"):
    return SimpleNamespace(
        id=eid,
        authorization=SimpleNamespace(
            spend_budget=spend_budget,
            rate_limits=SimpleNamespace(max_concurrent_sessions=sessions),
        ),
    )


def svc(tmp_path, name="ra.db"):
    return ReservationService(SqliteRepository(str(tmp_path / name)))


def add_grant(repo, eid="e1", *, single_use=True, used=False, revoked=False, expires_at=None,
              action=ACTION, target=TARGET) -> ApprovalGrant:
    g = ApprovalGrant(
        grant_id=uuid.uuid4().hex, action=action, target=_safe_host(target),
        tokens=frozenset({"tok"}), granted_by="op", granted_at=datetime.now(timezone.utc),
        expires_at=expires_at, single_use=single_use, used=used, revoked=revoked,
    )
    repo.save_grant(eid, g)
    return g


def test_reservation_consumes_the_single_use_approval(tmp_path):
    s = svc(tmp_path)
    add_grant(s._repo)
    r = s.reserve(eng(), spend=1.0, idempotency_key="k1", consume_approval=APPROVAL)
    assert r is not None
    assert s._repo.list_grants("e1")[0].used is True


def test_a_burned_approval_cannot_be_reused(tmp_path):
    s = svc(tmp_path)
    add_grant(s._repo)
    assert s.reserve(eng(), idempotency_key="k1", consume_approval=APPROVAL) is not None
    # second reservation finds the token spent -> fail closed, no reservation
    assert s.reserve(eng(), idempotency_key="k2", consume_approval=APPROVAL) is None
    assert s._repo.reservation_usage("e1")[1] == 1  # only the first holds a session


def test_concurrent_reservations_only_one_consumes(tmp_path):
    s = svc(tmp_path)
    add_grant(s._repo)
    results: list = []
    lock = threading.Lock()

    def worker(i):
        r = s.reserve(eng(), sessions=1, idempotency_key=f"k{i}", consume_approval=APPROVAL)
        with lock:
            results.append(r)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sum(1 for r in results if r is not None) == 1  # exactly one winner
    assert s._repo.list_grants("e1")[0].used is True


def test_missing_approval_fails_closed(tmp_path):
    s = svc(tmp_path)  # no grant at all
    assert s.reserve(eng(), idempotency_key="k1", consume_approval=APPROVAL) is None
    assert s._repo.reservation_usage("e1") == (0.0, 0)  # nothing claimed


@pytest.mark.parametrize("kwargs", [
    {"revoked": True},
    {"used": True},
    {"expires_at": datetime.now(timezone.utc) - timedelta(minutes=1)},
    {"single_use": False},  # a standing grant is not a single-use token to burn
])
def test_inactive_or_nonmatching_grant_is_not_consumable(tmp_path, kwargs):
    s = svc(tmp_path)
    add_grant(s._repo, **kwargs)
    assert s.reserve(eng(), idempotency_key="k1", consume_approval=APPROVAL) is None
    assert s._repo.reservation_usage("e1") == (0.0, 0)


def test_cap_exceeded_does_not_burn_the_approval(tmp_path):
    s = svc(tmp_path)
    add_grant(s._repo)
    r = s.reserve(eng(spend_budget=5.0), spend=10.0, idempotency_key="k1", consume_approval=APPROVAL)
    assert r is None
    assert s._repo.list_grants("e1")[0].used is False  # token preserved for a real claim


def test_idempotent_retry_does_not_reconsume(tmp_path):
    s = svc(tmp_path)
    add_grant(s._repo)
    r1 = s.reserve(eng(), idempotency_key="k1", consume_approval=APPROVAL)
    r2 = s.reserve(eng(), idempotency_key="k1", consume_approval=APPROVAL)  # same key
    assert r1 is not None and r2 is not None and r1.reservation_id == r2.reservation_id
    assert s._repo.list_grants("e1")[0].used is True


# --- postgres parity (gated) -------------------------------------------------

import os  # noqa: E402

DSN = os.environ.get("AEGIS_TEST_POSTGRES_DSN")


@pytest.mark.skipif(not DSN, reason="set AEGIS_TEST_POSTGRES_DSN to run")
def test_concurrent_single_use_consumption_on_postgres():
    pytest.importorskip("psycopg")
    from aegis.api.postgres import PostgresRepository

    repo = PostgresRepository(DSN)
    repo._exec("TRUNCATE grants, reservations CASCADE")
    try:
        add_grant(repo)
        s = ReservationService(repo)
        results: list = []
        lock = threading.Lock()

        def worker(i):
            r = s.reserve(eng(), sessions=1, idempotency_key=f"k{i}", consume_approval=APPROVAL)
            with lock:
                results.append(r)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sum(1 for r in results if r is not None) == 1
        assert repo.list_grants("e1")[0].used is True
    finally:
        repo.close()
