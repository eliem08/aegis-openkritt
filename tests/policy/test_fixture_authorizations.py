from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from aegis.policy.authorization import (
    Authorization,
    CloudFixtureConfig,
    DataHandling,
    Environment,
    PassiveProviderConfig,
    RateLimits,
)
from aegis.policy.scope import ScopeGuard


def _base_auth_kwargs() -> dict:
    now = datetime.now(UTC)
    return {
        "customer_id": "cust-fixture",
        "authorization_id": "auth-fixture-001",
        "ownership_proof": ["dns:fixture.test"],
        "targets": ["127.0.0.1", "localhost"],
        "valid_from": now - timedelta(hours=1),
        "valid_until": now + timedelta(hours=1),
        "rate_limits": RateLimits(requests_per_second=10.0, max_concurrent_sessions=2),
        "data_handling": DataHandling(),
    }


def test_operator_owned_cloud_fixture_validation() -> None:
    kwargs = _base_auth_kwargs()
    kwargs["environment"] = Environment.OPERATOR_OWNED_CLOUD_FIXTURE

    # Missing cloud_fixture config raises ValueError
    with pytest.raises(ValidationError, match="cloud_fixture config required"):
        Authorization(**kwargs)

    # Budget over $10.00 raises ValueError
    with pytest.raises(ValidationError):
        CloudFixtureConfig(
            provider="aws",
            account_id="123456789012",
            max_cost_usd=15.0,  # exceeds le=10.0
        )

    # Valid cloud fixture auth
    cloud_cfg = CloudFixtureConfig(
        provider="aws",
        account_id="123456789012",
        resource_scope=["arn:aws:s3:::aegis-fixture-test"],
        max_cost_usd=5.0,
        allowed_scanners=["prowler", "scoutsuite"],
        teardown_required=True,
    )
    kwargs["cloud_fixture"] = cloud_cfg
    auth = Authorization(**kwargs)
    assert auth.environment is Environment.OPERATOR_OWNED_CLOUD_FIXTURE
    assert auth.cloud_fixture is not None
    assert auth.cloud_fixture.max_cost_usd <= 10.0


def test_passive_provider_fixture_validation() -> None:
    kwargs = _base_auth_kwargs()
    kwargs["environment"] = Environment.PASSIVE_PROVIDER_FIXTURE

    # Missing passive_provider config raises ValueError
    with pytest.raises(ValidationError, match="passive_provider config required"):
        Authorization(**kwargs)

    # Valid passive provider auth
    provider_cfg = PassiveProviderConfig(
        operator_domain="fixture.aegis.internal",
        allowed_sources=["wayback", "commoncrawl"],
        max_requests=20,
        passive_only=True,
    )
    kwargs["passive_provider"] = provider_cfg
    kwargs["targets"] = ["fixture.aegis.internal"]
    auth = Authorization(**kwargs)
    assert auth.environment is Environment.PASSIVE_PROVIDER_FIXTURE
    assert auth.passive_provider is not None
    assert auth.passive_provider.passive_only is True


def test_scope_guard_fixture_boundary() -> None:
    guard = ScopeGuard.for_fixture(["*.fixture.aegis.internal"])
    assert guard.is_allowed("127.0.0.1")
    assert guard.is_allowed("localhost")
    assert guard.is_allowed("::1")
    assert guard.is_allowed("test.fixture.aegis.internal")

    # Public targets and arbitrary domains fail closed
    assert not guard.is_allowed("example.com")
    assert not guard.is_allowed("google.com")
    assert not guard.is_allowed("8.8.8.8")
    assert not guard.is_allowed("192.0.2.1")


def test_is_loopback_or_private() -> None:
    assert ScopeGuard.is_loopback_or_private("127.0.0.1")
    assert ScopeGuard.is_loopback_or_private("localhost")
    assert ScopeGuard.is_loopback_or_private("10.0.0.1")
    assert ScopeGuard.is_loopback_or_private("192.168.1.100")
    assert ScopeGuard.is_loopback_or_private("172.16.0.1")
    assert ScopeGuard.is_loopback_or_private("::1")

    assert not ScopeGuard.is_loopback_or_private("8.8.8.8")
    assert not ScopeGuard.is_loopback_or_private("example.com")
    assert not ScopeGuard.is_loopback_or_private("github.com")
