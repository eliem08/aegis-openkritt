"""Postgres integration tests — same durability guarantees as SQLite.

Skipped unless a reachable Postgres is provided via ``AEGIS_TEST_POSTGRES_DSN``
(the docker-compose ``postgres`` service works). These are the *real* validation
that the Postgres repository behaves identically to SQLite across a restart.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("psycopg")
DSN = os.environ.get("AEGIS_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="set AEGIS_TEST_POSTGRES_DSN to run")

from aegis.api.postgres import PostgresRepository  # noqa: E402
from aegis.api.store import ApprovalGrant, EngagementRecord, EngagementStore  # noqa: E402
from aegis.policy import ActionRequest, Authorization, HmacSignatureVerifier, Verdict  # noqa: E402
from aegis.policy.killswitch import KillSwitchState  # noqa: E402

KID, SECRET = "kid-pg", "pg-secret"


@pytest.fixture(autouse=True)
def clean():
    repo = PostgresRepository(DSN)
    repo._exec(
        "TRUNCATE engagements, grants, audit, kill_state, spend, reservations, "
        "scan_runs, stage_runs, task_runs, task_leases, artifacts CASCADE"
    )
    repo.close()
    yield


def _verifier() -> HmacSignatureVerifier:
    return HmacSignatureVerifier({KID: SECRET})


def signed_auth(aid: str = "auth-pg", spend: float = 100.0) -> Authorization:
    now = datetime.now(timezone.utc)
    a = Authorization(
        customer_id="c", authorization_id=aid, ownership_proof=["dns"],
        targets=["api.example.test"], valid_from=now - timedelta(days=1), valid_until=now + timedelta(days=10),
        permitted_actions=["passive_discovery", "cross_tenant_proof"], prohibited_actions=["denial_of_service"],
        rate_limits={"requests_per_second": 5, "max_concurrent_sessions": 3},
        approval_required_for=["cross_tenant_proof"], spend_budget=spend,
    )
    a.signature = _verifier().sign(a.signing_payload(), KID)
    a.signing_key_id = KID
    return a


def store() -> EngagementStore:
    return EngagementStore(verifier=_verifier(), require_signature=True, repository=PostgresRepository(DSN))


# --- repository-level ---

def test_pg_engagement_and_grant_roundtrip():
    repo = PostgresRepository(DSN)
    repo.save_engagement(EngagementRecord(id="e1", authorization={"x": 1}, status="active",
                                          created_at=datetime.now(timezone.utc)))
    assert repo.get_engagement("e1").authorization == {"x": 1}
    g = ApprovalGrant(grant_id="g1", action="a", target="h", tokens=frozenset({"t"}),
                      granted_by="op", granted_at=datetime.now(timezone.utc))
    repo.save_grant("e1", g)
    assert repo.list_grants("e1")[0].tokens == frozenset({"t"})
    g.revoked = True
    repo.save_grant("e1", g)  # upsert via ON CONFLICT
    assert repo.list_grants("e1")[0].revoked is True


def test_pg_kill_spend_audit():
    repo = PostgresRepository(DSN)
    assert repo.get_kill_state("e1") is None
    repo.save_kill_state("e1", KillSwitchState(fired=True, reason="stop", source="op",
                                               fired_at=datetime.now(timezone.utc)))
    assert repo.get_kill_state("e1").reason == "stop"
    repo.save_spend("e1", 42.5)
    assert repo.get_spend("e1") == 42.5
    for i in range(5):
        repo.append_audit("e1", {"n": i})
    assert [r["n"] for r in repo.recent_audit("e1", 3)] == [2, 3, 4]


# --- store-level durability across a 'restart' ---

def test_pg_state_survives_restart():
    now = datetime.now(timezone.utc)
    e1 = store().create(signed_auth())
    e1.approvals.grant(action="cross_tenant_proof", target="api.example.test",
                       tokens=["cross_tenant_proof", "tier:SENSITIVE"], granted_by="op")
    req = ActionRequest(target="api.example.test", action="passive_discovery", estimated_cost=30.0)
    d = e1.engine.authorize(req, now=now)
    e1.engine.commit(d, request=req, now=now)
    e1.engine.kill_switch.fire("operator stop")

    e2 = store().get("auth-pg")  # new store + connection = restart
    assert e2.approvals.tokens_for("cross_tenant_proof", "api.example.test", now) == {
        "cross_tenant_proof", "tier:SENSITIVE"
    }
    denied = e2.engine.authorize(ActionRequest(target="api.example.test", action="passive_discovery"), now=now)
    assert denied.verdict == Verdict.DENY and "KILL_SWITCH" in denied.incidents
    assert len(e2.audit.recent()) >= 1
    e2.engine.kill_switch.reset()
    over = e2.engine.authorize(
        ActionRequest(target="api.example.test", action="passive_discovery", estimated_cost=90.0), now=now
    )
    assert over.verdict == Verdict.DENY  # 30 already spent + 90 > 100


# --- atomic reservations against real Postgres ---

def test_pg_reservations_no_overbooking():
    import threading
    from types import SimpleNamespace

    from aegis.api.reservations import ReservationService

    e = SimpleNamespace(id="res-eng", authorization=SimpleNamespace(
        spend_budget=100.0, rate_limits=SimpleNamespace(max_concurrent_sessions=10_000)))
    results: list = []
    lock = threading.Lock()

    def worker(i):
        s = ReservationService(PostgresRepository(DSN))  # own pool/connection per thread
        r = s.reserve(e, spend=10.0, sessions=1, idempotency_key=f"k{i}")
        with lock:
            results.append(r)
        s._repo.close()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len([r for r in results if r is not None]) == 10  # advisory lock prevents overbooking
    assert ReservationService(PostgresRepository(DSN)).usage("res-eng")[0] == 100.0


def test_pg_reservation_idempotent_and_finalize():
    from types import SimpleNamespace

    from aegis.api.reservations import ReservationService

    s = ReservationService(PostgresRepository(DSN))
    e = SimpleNamespace(id="res-eng2", authorization=SimpleNamespace(
        spend_budget=100.0, rate_limits=SimpleNamespace(max_concurrent_sessions=5)))
    a = s.reserve(e, spend=10, idempotency_key="dup")
    b = s.reserve(e, spend=10, idempotency_key="dup")
    assert a.reservation_id == b.reservation_id
    s.finalize(a.reservation_id, 6.0)
    assert s.usage("res-eng2")[0] == 6.0  # actual, remainder released


# --- durable scan model against real Postgres ---

def test_pg_scan_model_lease_and_restart_recovery():
    from datetime import timedelta

    from aegis.api.scans import new_scan, new_stage, new_task
    from aegis.api.store import EngagementRecord

    repo = PostgresRepository(DSN)
    repo.save_engagement(EngagementRecord(id="eng-pg", authorization={"customer_id": "t"},
                                          status="active", created_at=datetime.now(timezone.utc)))
    scan = new_scan(tenant_id="t", engagement_id="eng-pg")
    repo.create_scan(scan)
    stage = new_stage(scan_id=scan.scan_id, stage_type="probe")
    repo.create_stage(stage)

    t1 = repo.create_task(new_task(scan_id=scan.scan_id, stage_id=stage.stage_id, target="a",
                                   adapter="f", adapter_version="1", input_hash="h1"))
    # idempotent create returns the same task
    again = repo.create_task(new_task(scan_id=scan.scan_id, stage_id=stage.stage_id, target="a",
                                      adapter="f", adapter_version="1", input_hash="h1"))
    assert again.task_id == t1.task_id

    assert repo.lease_task(t1.task_id, "w1", ttl_seconds=1) is not None
    assert repo.lease_task(t1.task_id, "w2", ttl_seconds=1) is None  # compare-and-set

    future = datetime.now(timezone.utc) + timedelta(seconds=60)
    reclaimed = dict(repo.reclaim_expired_leases(now=future))
    assert reclaimed.get(t1.task_id) == "queued"
    assert repo.get_task(t1.task_id).attempts == 1
    repo.close()
