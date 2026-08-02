"""API and operational protection (Phase 5): body limits, rate limits, pagination
caps, per-tenant quotas, short-lived service identities, and audited break-glass."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aegis.api.protection import (
    BodyTooLarge,
    BreakGlass,
    ProtectionLimits,
    QuotaExceeded,
    RateLimited,
    ServiceIdentity,
    TenantProtection,
    clamp_page_size,
    enforce_body_size,
)

NOW = datetime(2026, 8, 2, tzinfo=timezone.utc)


class Clock:
    def __init__(self):
        self.now = NOW

    def __call__(self):
        return self.now

    def advance(self, s):
        self.now += timedelta(seconds=s)


# --- body size + pagination --------------------------------------------------

def test_oversized_body_is_rejected():
    limits = ProtectionLimits(max_body_bytes=100)
    enforce_body_size(100, limits)
    with pytest.raises(BodyTooLarge):
        enforce_body_size(101, limits)


def test_pagination_is_always_capped():
    limits = ProtectionLimits(max_page_size=200, default_page_size=50)
    assert clamp_page_size(None, limits) == 50
    assert clamp_page_size(10, limits) == 10
    assert clamp_page_size(10_000, limits) == 200      # clamped, never honored
    assert clamp_page_size(-5, limits) == 50


# --- per-tenant rate limits + quotas ----------------------------------------

def test_rate_limit_is_per_tenant():
    clock = Clock()
    p = TenantProtection(ProtectionLimits(requests_per_minute=2), clock=clock)
    p.check_rate("tenant-a")
    p.check_rate("tenant-a")
    with pytest.raises(RateLimited):
        p.check_rate("tenant-a")
    p.check_rate("tenant-b")               # a different tenant is unaffected


def test_rate_window_resets():
    clock = Clock()
    p = TenantProtection(ProtectionLimits(requests_per_minute=1), clock=clock)
    p.check_rate("t")
    with pytest.raises(RateLimited):
        p.check_rate("t")
    clock.advance(61)
    p.check_rate("t")                      # window rolled over


def test_daily_quota_is_enforced_per_tenant():
    p = TenantProtection(ProtectionLimits(daily_scan_quota=2))
    assert p.consume_quota("tenant-a") == 1 and p.consume_quota("tenant-a") == 2
    with pytest.raises(QuotaExceeded):
        p.consume_quota("tenant-a")
    assert p.consume_quota("tenant-b") == 1        # separate budget
    assert p.quota_used("tenant-a") == 2


# --- service identities ------------------------------------------------------

def test_service_identity_is_short_lived_and_scoped():
    ident = ServiceIdentity("worker-svc", tenant_id="t", issued_at=NOW,
                            expires_at=NOW + timedelta(minutes=15), scopes=("lease", "heartbeat"))
    assert ident.valid(NOW, scope="lease")
    assert not ident.valid(NOW, scope="admin")             # scope not granted
    assert not ident.valid(NOW + timedelta(hours=1))       # expired


# --- break-glass -------------------------------------------------------------

def test_break_glass_is_time_limited_and_audited():
    bg = BreakGlass(operator="op", reason="incident-42", expires_at=NOW + timedelta(minutes=30))
    assert bg.use("disable_tenant", now=NOW) is True
    assert bg.use("disable_tenant", now=NOW + timedelta(hours=1)) is False   # expired
    assert len(bg.audit) == 2 and bg.audit[0]["reason"] == "incident-42"
