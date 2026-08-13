"""Fail-closed authority helpers for isolated arsenal fixtures."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from urllib.parse import urlsplit

from aegis.policy.authorization import Authorization, DataHandling, Environment, RateLimits

LOCAL_FIXTURE_ONLY = "LOCAL_FIXTURE_ONLY"


def is_isolated_destination(value: str) -> bool:
    """Return true only for loopback destinations; names are rejected to avoid DNS ambiguity."""
    parsed = urlsplit(value if "://" in value else f"https://{value}")
    host = (parsed.hostname or "").strip().casefold()
    if host == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


class LocalFixtureSignatureVerifier:
    """Signature verifier that also enforces the local-fixture authorization boundary."""

    def __init__(self, delegate) -> None:
        self.delegate = delegate

    def sign(self, payload: dict, key_id: str) -> str:
        return self.delegate.sign(payload, key_id)

    def verify(self, payload: dict, signature: str | None, key_id: str | None) -> bool:
        if not self.delegate.verify(payload, signature, key_id):
            return False
        if "constraints" in payload:  # ExecutionGrant payload
            constraints = dict(payload.get("constraints") or {})
            if constraints.get("authorization_class") != LOCAL_FIXTURE_ONLY:
                return False
            destinations = tuple(str(item) for item in payload.get("allowed_destinations") or ())
            return all(is_isolated_destination(item) for item in destinations)
        if payload.get("environment") != Environment.LOCAL_FIXTURE_ONLY.value:
            return False
        return all(is_isolated_destination(item) for item in payload.get("targets") or ())


def signed_fixture_authorization(verifier, *, now: datetime | None = None) -> Authorization:
    observed = (now or datetime.now(UTC)).astimezone(UTC)
    authorization = Authorization(
        customer_id="aegis-local-fixture",
        authorization_id=f"fixture:{observed.strftime('%Y%m%dT%H%M%SZ')}",
        ownership_proof=["local fixture created by the operator process"],
        targets=["127.0.0.1"],
        environment=Environment.LOCAL_FIXTURE_ONLY,
        valid_from=observed - timedelta(seconds=5),
        valid_until=observed + timedelta(minutes=15),
        permitted_actions=["source_analysis"],
        prohibited_actions=[
            "denial_of_service", "persistence", "production_data_exfiltration",
            "third_party_targeting", "credential_bruteforce", "lateral_movement",
            "log_tampering",
        ],
        rate_limits=RateLimits(requests_per_second=1.0, max_concurrent_sessions=1),
        data_handling=DataHandling(stop_on_real_pii=True, evidence_retention_days=30),
        spend_budget=0.0,
        signing_key_id="fixture-auth",
    )
    signature = verifier.sign(authorization.signing_payload(), "fixture-auth")
    return authorization.model_copy(update={"signature": signature})


__all__ = [
    "LOCAL_FIXTURE_ONLY", "LocalFixtureSignatureVerifier", "is_isolated_destination",
    "signed_fixture_authorization",
]
