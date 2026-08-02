"""Scan API — the Phase 1 completion gate, driven through the real HTTP surface.

A fake discovery adapter runs through create -> run-next (reservation, lease,
process, event, quarantine, normalization, persistence) -> read, plus cancel and
recover, all tenant-scoped and role-gated. SQLite here; a gated Postgres variant
proves parity.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from aegis.api import ApiPrincipal, ControlPlaneConfig, Role, create_app
from aegis.policy import Authorization, HmacSignatureVerifier

KID, SECRET = "kid-scan", "scan-secret"

OPA = {"Authorization": "Bearer opA"}
AGA = {"Authorization": "Bearer agA"}
WKA = {"Authorization": "Bearer wkA"}
AGB = {"Authorization": "Bearer agB"}
WKB = {"Authorization": "Bearer wkB"}
OPB = {"Authorization": "Bearer opB"}

TARGETS = ["api.example.test", "secret.example.test"]


def make_config(tmp_path, name="scans.db") -> ControlPlaneConfig:
    return ControlPlaneConfig(
        api_keys={
            "opA": ApiPrincipal("opA", Role.OPERATOR, tenant_id="tenant-a"),
            "agA": ApiPrincipal("agA", Role.AGENT, tenant_id="tenant-a"),
            "wkA": ApiPrincipal("wkA", Role.WORKER, tenant_id="tenant-a"),
            "opB": ApiPrincipal("opB", Role.OPERATOR, tenant_id="tenant-b"),
            "agB": ApiPrincipal("agB", Role.AGENT, tenant_id="tenant-b"),
            "wkB": ApiPrincipal("wkB", Role.WORKER, tenant_id="tenant-b"),
        },
        signing_keys={KID: SECRET},
        db_path=str(tmp_path / name),
    )


@pytest.fixture
def client(tmp_path) -> TestClient:
    return TestClient(create_app(make_config(tmp_path)))


def signed_auth(aid: str, customer_id: str, targets=TARGETS) -> dict:
    now = datetime.now(timezone.utc)
    a = Authorization(
        customer_id=customer_id, authorization_id=aid, ownership_proof=["dns"],
        targets=list(targets), valid_from=now - timedelta(days=1), valid_until=now + timedelta(days=10),
        permitted_actions=["passive_discovery"], prohibited_actions=["denial_of_service"],
        rate_limits={"requests_per_second": 5, "max_concurrent_sessions": 3},
        spend_budget=100.0,
    )
    a.signature = HmacSignatureVerifier({KID: SECRET}).sign(a.signing_payload(), KID)
    a.signing_key_id = KID
    return a.model_dump(mode="json")


def register(client, aid="auth-a1", tenant="tenant-a", headers=OPA):
    r = client.post("/engagements", headers=headers, json=signed_auth(aid, tenant))
    assert r.status_code == 201, r.text
    return aid


def plan(engagement_id="auth-a1", target="api.example.test", est_spend=1.0, adapter="fake-discovery"):
    return {
        "engagement_id": engagement_id,
        "stages": [{"key": "recon", "stage_type": "discovery"}],
        "tasks": [{"adapter": adapter, "target": target, "stage": "recon", "est_spend": est_spend}],
    }


def run_to_quiescence(client, scan_id, headers=WKA, cap=10):
    steps = []
    for _ in range(cap):
        r = client.post(f"/scans/{scan_id}/run-next", headers=headers)
        assert r.status_code == 200, r.text
        body = r.json()
        if not body["ran"]:
            break
        steps.append(body)
    return steps


# --- the gate: full scan through the API ------------------------------------

def test_full_scan_through_the_api(client):
    register(client)
    r = client.post("/scans", headers=AGA, json=plan())
    assert r.status_code == 201, r.text
    scan_id = r.json()["scan_id"]
    assert r.json()["tenant_id"] == "tenant-a"

    steps = run_to_quiescence(client, scan_id)
    assert [s["outcome"] for s in steps] == ["succeeded"]

    detail = client.get(f"/scans/{scan_id}", headers=AGA).json()
    assert detail["status"] == "created"
    assert [t["status"] for t in detail["tasks"]] == ["succeeded"]
    assert len(detail["artifacts"]) == 1 and detail["artifacts"][0]["classification"] == "clean"
    # sanitized: no raw payload / storage reference leaks into scan responses
    assert "storage_ref" not in detail["artifacts"][0]


def test_scan_appears_in_tenant_list(client):
    register(client)
    scan_id = client.post("/scans", headers=AGA, json=plan()).json()["scan_id"]
    ids = {s["scan_id"] for s in client.get("/scans", headers=AGA).json()}
    assert scan_id in ids
    # other tenant sees nothing of tenant-a's
    assert client.get("/scans", headers=AGB).json() == []


# --- role gating -------------------------------------------------------------

def test_worker_role_required_to_run_tasks(client):
    register(client)
    scan_id = client.post("/scans", headers=AGA, json=plan()).json()["scan_id"]
    assert client.post(f"/scans/{scan_id}/run-next", headers=AGA).status_code == 403  # agent
    assert client.post(f"/scans/{scan_id}/run-next", headers=OPA).status_code == 403  # operator
    assert client.post(f"/scans/{scan_id}/run-next", headers=WKA).status_code == 200  # worker


def test_worker_cannot_plan_scans(client):
    register(client)
    assert client.post("/scans", headers=WKA, json=plan()).status_code == 403


def test_only_operator_can_cancel(client):
    register(client)
    scan_id = client.post("/scans", headers=AGA, json=plan()).json()["scan_id"]
    assert client.post(f"/scans/{scan_id}/cancel", headers=AGA).status_code == 403
    r = client.post(f"/scans/{scan_id}/cancel", headers=OPA)
    assert r.status_code == 200 and r.json()["cancelled"] == 1
    detail = client.get(f"/scans/{scan_id}", headers=AGA).json()
    assert detail["tasks"][0]["status"] == "cancelled"


# --- tenant isolation --------------------------------------------------------

def test_cross_tenant_scan_is_hidden(client):
    register(client)
    scan_id = client.post("/scans", headers=AGA, json=plan()).json()["scan_id"]
    assert client.get(f"/scans/{scan_id}", headers=AGB).status_code == 404
    assert client.post(f"/scans/{scan_id}/run-next", headers=WKB).status_code == 404
    assert client.post(f"/scans/{scan_id}/cancel", headers=OPB).status_code == 404


def test_cannot_plan_against_another_tenants_engagement(client):
    register(client)  # engagement in tenant-a
    assert client.post("/scans", headers=AGB, json=plan()).status_code == 404


# --- plan validation ---------------------------------------------------------

def test_out_of_scope_target_rejected(client):
    register(client)
    bad = plan(target="evil.example.test")
    r = client.post("/scans", headers=AGA, json=bad)
    assert r.status_code == 422 and "authorization" in r.json()["detail"]


def test_unknown_adapter_rejected(client):
    register(client)
    r = client.post("/scans", headers=AGA, json=plan(adapter="nmap"))
    assert r.status_code == 422 and "adapter" in r.json()["detail"]


# --- quarantine through the API ----------------------------------------------

def test_sensitive_signal_quarantines_via_api(client):
    register(client)
    scan_id = client.post("/scans", headers=AGA, json=plan(target="secret.example.test")).json()["scan_id"]
    steps = run_to_quiescence(client, scan_id)
    assert steps[0]["outcome"] == "quarantined"
    detail = client.get(f"/scans/{scan_id}", headers=AGA).json()
    assert detail["tasks"][0]["status"] == "quarantined"
    assert detail["artifacts"][0]["classification"] == "quarantined"


# --- worker lease heartbeat --------------------------------------------------

def test_heartbeat_extends_a_workers_lease(client):
    register(client)
    scan_id = client.post("/scans", headers=AGA, json=plan()).json()["scan_id"]
    task_id = client.get(f"/scans/{scan_id}", headers=AGA).json()["tasks"][0]["task_id"]

    # A worker leased the task (out-of-band execution model).
    client.app.state.repository.lease_task(task_id, "wkA", ttl_seconds=300)

    r = client.post(f"/tasks/{task_id}/heartbeat", headers=WKA)
    assert r.status_code == 200 and r.json()["extended"] is True
    # cross-tenant worker cannot even see the task
    assert client.post(f"/tasks/{task_id}/heartbeat", headers=WKB).status_code == 404
    # non-worker rejected
    assert client.post(f"/tasks/{task_id}/heartbeat", headers=AGA).status_code == 403


# --- restart recovery through the API ----------------------------------------

def test_recover_reclaims_expired_lease_then_runs(client):
    register(client)
    scan_id = client.post("/scans", headers=AGA, json=plan()).json()["scan_id"]
    task_id = client.get(f"/scans/{scan_id}", headers=AGA).json()["tasks"][0]["task_id"]

    # A crashed worker left an already-expired lease on a running task.
    repo = client.app.state.repository
    repo.lease_task(task_id, "wkA", ttl_seconds=-5)
    repo.transition_task(task_id, "running")

    r = client.post(f"/scans/{scan_id}/recover", headers=WKA)
    assert r.status_code == 200 and task_id in r.json()["reclaimed"]

    steps = run_to_quiescence(client, scan_id)
    assert steps[-1]["outcome"] == "succeeded"


# --- raw artifact access gate ------------------------------------------------

def test_raw_artifact_requires_operator_and_explicit_review(client):
    register(client)
    scan_id = client.post("/scans", headers=AGA, json=plan(target="secret.example.test")).json()["scan_id"]
    run_to_quiescence(client, scan_id)
    artifact_id = client.get(f"/scans/{scan_id}", headers=AGA).json()["artifacts"][0]["artifact_id"]

    body = {"action": "quarantine_review", "justification": "reviewing a flagged secret"}
    # agent cannot reach raw access at all
    assert client.post(f"/artifacts/{artifact_id}/raw", headers=AGA, json=body).status_code == 403
    # operator without the explicit action is refused
    assert client.post(f"/artifacts/{artifact_id}/raw", headers=OPA,
                       json={"action": "peek", "justification": "x"}).status_code == 403
    # operator with the explicit review action succeeds
    r = client.post(f"/artifacts/{artifact_id}/raw", headers=OPA, json=body)
    assert r.status_code == 200 and r.json()["classification"] == "quarantined"


# --- durability requirement --------------------------------------------------

def test_scans_require_a_database():
    cfg = ControlPlaneConfig(
        api_keys={"agA": ApiPrincipal("agA", Role.AGENT, tenant_id="tenant-a")},
        signing_keys={KID: SECRET},  # no db_path -> in-memory
    )
    c = TestClient(create_app(cfg))
    assert c.get("/scans", headers=AGA).status_code == 503


# --- postgres parity (gated) -------------------------------------------------

DSN = os.environ.get("AEGIS_TEST_POSTGRES_DSN")


@pytest.mark.skipif(not DSN, reason="set AEGIS_TEST_POSTGRES_DSN to run")
def test_full_scan_through_the_api_on_postgres():
    pytest.importorskip("psycopg")
    from aegis.api.postgres import PostgresRepository

    PostgresRepository(DSN)._exec(
        "TRUNCATE engagements, grants, audit, kill_state, spend, reservations, "
        "scan_runs, stage_runs, task_runs, task_leases, artifacts CASCADE"
    )
    cfg = ControlPlaneConfig(
        api_keys={
            "opA": ApiPrincipal("opA", Role.OPERATOR, tenant_id="tenant-a"),
            "agA": ApiPrincipal("agA", Role.AGENT, tenant_id="tenant-a"),
            "wkA": ApiPrincipal("wkA", Role.WORKER, tenant_id="tenant-a"),
        },
        signing_keys={KID: SECRET},
        db_url=DSN,
    )
    with TestClient(create_app(cfg)) as client:
        register(client)
        scan_id = client.post("/scans", headers=AGA, json=plan()).json()["scan_id"]
        steps = run_to_quiescence(client, scan_id)
        assert [s["outcome"] for s in steps] == ["succeeded"]
        detail = client.get(f"/scans/{scan_id}", headers=AGA).json()
        assert detail["tasks"][0]["status"] == "succeeded"
        assert detail["artifacts"][0]["classification"] == "clean"
