"""Tenant binding: cross-tenant access is denied; single-tenant compat unchanged."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from aegis.api import ApiPrincipal, ControlPlaneConfig, Role, create_app
from aegis.policy import Authorization, HmacSignatureVerifier

KID, SECRET = "kid-t", "tenant-secret"

OPA = {"Authorization": "Bearer opA"}
AGA = {"Authorization": "Bearer agA"}
OPB = {"Authorization": "Bearer opB"}
AGB = {"Authorization": "Bearer agB"}
ADMIN = {"Authorization": "Bearer admin"}


def multi_tenant_config() -> ControlPlaneConfig:
    return ControlPlaneConfig(
        api_keys={
            "opA": ApiPrincipal("opA", Role.OPERATOR, tenant_id="tenant-a"),
            "agA": ApiPrincipal("agA", Role.AGENT, tenant_id="tenant-a"),
            "opB": ApiPrincipal("opB", Role.OPERATOR, tenant_id="tenant-b"),
            "agB": ApiPrincipal("agB", Role.AGENT, tenant_id="tenant-b"),
            "admin": ApiPrincipal("admin", Role.SYSTEM_ADMIN, tenant_id="tenant-a"),
        },
        signing_keys={KID: SECRET},
    )


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(multi_tenant_config()))


def signed_auth(aid: str, customer_id: str) -> dict:
    now = datetime.now(timezone.utc)
    a = Authorization(
        customer_id=customer_id, authorization_id=aid, ownership_proof=["dns"],
        targets=["api.example.test"], valid_from=now - timedelta(days=1), valid_until=now + timedelta(days=10),
        permitted_actions=["passive_discovery"], prohibited_actions=["denial_of_service"],
        rate_limits={"requests_per_second": 5, "max_concurrent_sessions": 3},
    )
    a.signature = HmacSignatureVerifier({KID: SECRET}).sign(a.signing_payload(), KID)
    a.signing_key_id = KID
    return a.model_dump(mode="json")


def _decide(client, headers, eid):
    return client.post(f"/engagements/{eid}/decisions", headers=headers,
                       json={"target": "api.example.test", "action": "passive_discovery"})


def test_config_is_multi_tenant():
    assert multi_tenant_config().is_single_tenant_compat is False


def test_cross_tenant_access_is_denied(client):
    assert client.post("/engagements", headers=OPA, json=signed_auth("auth-a1", "tenant-a")).status_code == 201
    # same tenant works
    assert client.get("/engagements/auth-a1", headers=AGA).status_code == 200
    assert _decide(client, AGA, "auth-a1").status_code == 200
    # other tenant is hidden (404, not 403 — no existence leak)
    assert client.get("/engagements/auth-a1", headers=AGB).status_code == 404
    assert _decide(client, AGB, "auth-a1").status_code == 404


def test_operator_cannot_register_for_another_tenant(client):
    # opB (tenant-b) tries to register an authorization whose customer_id is tenant-a
    r = client.post("/engagements", headers=OPB, json=signed_auth("auth-x", "tenant-a"))
    assert r.status_code == 403


def test_list_is_scoped_to_the_callers_tenant(client):
    client.post("/engagements", headers=OPA, json=signed_auth("auth-a2", "tenant-a"))
    client.post("/engagements", headers=OPB, json=signed_auth("auth-b1", "tenant-b"))
    ids = {e["id"] for e in client.get("/engagements", headers=AGA).json()}
    assert "auth-a2" in ids and "auth-b1" not in ids


def test_system_admin_cannot_execute_scans(client):
    client.post("/engagements", headers=OPA, json=signed_auth("auth-a3", "tenant-a"))
    assert client.get("/engagements", headers=ADMIN).status_code == 403          # require_agent rejects
    assert client.get("/engagements/auth-a3", headers=ADMIN).status_code == 403
    assert client.post("/engagements", headers=ADMIN, json=signed_auth("z", "tenant-a")).status_code == 403


def test_single_tenant_compat_has_no_isolation():
    cfg = ControlPlaneConfig(
        api_keys={"op": ApiPrincipal("op", Role.OPERATOR), "ag": ApiPrincipal("ag", Role.AGENT)},
        signing_keys={KID: SECRET},
    )
    assert cfg.is_single_tenant_compat is True
    c = TestClient(create_app(cfg))
    c.post("/engagements", headers={"Authorization": "Bearer op"}, json=signed_auth("auth-c", "any-customer"))
    # agent has no tenant, yet can access despite the customer_id — compat mode
    assert c.get("/engagements/auth-c", headers={"Authorization": "Bearer ag"}).status_code == 200
