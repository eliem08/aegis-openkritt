"""Shared builders for the policy-core tests.

Kept in a uniquely-named module (not ``conftest``) so ``from policy_helpers
import ...`` is unambiguous even with nested conftest.py files present.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from aegis.policy import Authorization, HmacSignatureVerifier

SIGNING_KEY_ID = "kid-test"
SIGNING_SECRET = "super-secret-control-plane-key"


def sign(
    auth: Authorization,
    verifier: HmacSignatureVerifier,
    key_id: str = SIGNING_KEY_ID,
) -> Authorization:
    """Sign an (unsigned) authorization in place and return it."""
    auth.signature = verifier.sign(auth.signing_payload(), key_id)
    auth.signing_key_id = key_id
    return auth


def make_authorization(now: datetime, **overrides) -> Authorization:
    base = dict(
        customer_id="customer-123",
        authorization_id="auth-2026-001",
        ownership_proof=["dns-txt", "signed-roe"],
        targets=["api.example.test", "app.example.test"],
        environment="staging",
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=29),
        permitted_actions=[
            "passive_discovery",
            "authenticated_testing",
            "synthetic_data_access",
            "safe_state_change",
            "cross_tenant_proof",
            "privilege_escalation",
            "custom_probe",  # permitted but unknown to the classifier
        ],
        prohibited_actions=[
            "denial_of_service",
            "persistence",
            "production_data_exfiltration",
            "third_party_targeting",
        ],
        rate_limits={"requests_per_second": 5, "max_concurrent_sessions": 3},
        approval_required_for=[
            "cross_tenant_proof",
            "server_side_request_forgery",
            "privilege_escalation",
        ],
        escalation_contacts=["secops@example.test"],
        spend_budget=100.0,
    )
    base.update(overrides)
    return Authorization(**base)
