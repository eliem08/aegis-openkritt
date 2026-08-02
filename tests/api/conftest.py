"""Fixtures for the control-plane API tests.

The API computes ``now`` internally from the real clock, so authorization
windows here are built relative to the live time (open 1 day ago, valid 30 days).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from aegis.api import ApiPrincipal, ControlPlaneConfig, Role, create_app
from aegis.policy import Authorization, HmacSignatureVerifier

OP_TOKEN = "operator-token-aaa"
AGENT_TOKEN = "agent-token-bbb"
SIGNING_KID = "kid-test"
SIGNING_SECRET = "control-plane-test-secret"


@pytest.fixture
def config() -> ControlPlaneConfig:
    return ControlPlaneConfig(
        api_keys={
            OP_TOKEN: ApiPrincipal("operator", Role.OPERATOR),
            AGENT_TOKEN: ApiPrincipal("agent", Role.AGENT),
        },
        signing_keys={SIGNING_KID: SIGNING_SECRET},
        require_signature=True,
        auth_enabled=True,
    )


@pytest.fixture
def client(config: ControlPlaneConfig) -> TestClient:
    return TestClient(create_app(config))


@pytest.fixture
def op_headers() -> dict:
    return {"Authorization": f"Bearer {OP_TOKEN}"}


@pytest.fixture
def agent_headers() -> dict:
    return {"Authorization": f"Bearer {AGENT_TOKEN}"}


def _verifier() -> HmacSignatureVerifier:
    return HmacSignatureVerifier({SIGNING_KID: SIGNING_SECRET})


@pytest.fixture
def make_signed_auth():
    """Factory: build a signed authorization JSON payload, with overrides."""

    def _make(**overrides) -> dict:
        now = datetime.now(timezone.utc)
        base = dict(
            customer_id="customer-123",
            authorization_id=f"auth-{uuid.uuid4().hex[:10]}",
            ownership_proof=["dns-txt", "signed-roe"],
            targets=["api.example.test", "app.example.test"],
            environment="staging",
            valid_from=now - timedelta(days=1),
            valid_until=now + timedelta(days=30),
            permitted_actions=[
                "passive_discovery",
                "authenticated_testing",
                "synthetic_data_access",
                "safe_state_change",
                "cross_tenant_proof",
                "custom_probe",
            ],
            prohibited_actions=[
                "denial_of_service",
                "persistence",
                "production_data_exfiltration",
                "third_party_targeting",
            ],
            rate_limits={"requests_per_second": 5, "max_concurrent_sessions": 3},
            approval_required_for=["cross_tenant_proof", "privilege_escalation"],
            escalation_contacts=["secops@example.test"],
            spend_budget=100.0,
        )
        base.update(overrides)
        auth = Authorization(**base)
        auth.signature = _verifier().sign(auth.signing_payload(), SIGNING_KID)
        auth.signing_key_id = SIGNING_KID
        return auth.model_dump(mode="json")

    return _make


@pytest.fixture
def registered(client: TestClient, op_headers: dict, make_signed_auth) -> dict:
    """Register a fresh engagement and return its authorization payload."""
    payload = make_signed_auth()
    resp = client.post("/engagements", headers=op_headers, json=payload)
    assert resp.status_code == 201, resp.text
    return payload
