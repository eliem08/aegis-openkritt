"""API and operational protection (Phase 5 §API and operational protection).

Per-tenant guardrails that sit in front of the control-plane API: request-body
size limits, API rate limits, pagination caps, and rolling tenant quotas. These
fail closed and are tenant-scoped, so one tenant can neither exhaust another's
budget nor evade a cap. Short-lived service identities and break-glass are modeled
here as explicit, audited allowances rather than ambient trust.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


class ProtectionError(RuntimeError):
    pass


class BodyTooLarge(ProtectionError):
    pass


class RateLimited(ProtectionError):
    pass


class QuotaExceeded(ProtectionError):
    pass


@dataclass(frozen=True)
class ProtectionLimits:
    max_body_bytes: int = 1_048_576          # 1 MiB
    requests_per_minute: int = 600
    max_page_size: int = 200
    default_page_size: int = 50
    daily_scan_quota: int = 100


def _now() -> datetime:
    return datetime.now(timezone.utc)


def enforce_body_size(size_bytes: int, limits: ProtectionLimits) -> None:
    if size_bytes > limits.max_body_bytes:
        raise BodyTooLarge(f"request body {size_bytes} exceeds {limits.max_body_bytes} bytes")


def clamp_page_size(requested: int | None, limits: ProtectionLimits) -> int:
    """Pagination is always capped; a missing/oversized value is clamped, not honored."""
    if requested is None or requested <= 0:
        return limits.default_page_size
    return min(int(requested), limits.max_page_size)


class TenantProtection:
    """Per-tenant rate limits and rolling quotas. Everything is keyed by tenant so
    tenants are isolated from each other."""

    def __init__(self, limits: ProtectionLimits | None = None, *, clock=None) -> None:
        self.limits = limits or ProtectionLimits()
        self._clock = clock or _now
        self._rate: dict[str, tuple[datetime, int]] = {}         # tenant -> (window_reset, count)
        self._quota: dict[tuple[str, str], int] = {}            # (tenant, resource) -> used

    def check_rate(self, tenant_id: str) -> None:
        now = self._clock()
        reset_at, count = self._rate.get(tenant_id, (now + timedelta(minutes=1), 0))
        if now >= reset_at:
            reset_at, count = now + timedelta(minutes=1), 0
        count += 1
        self._rate[tenant_id] = (reset_at, count)
        if count > self.limits.requests_per_minute:
            raise RateLimited(f"tenant {tenant_id!r} exceeded {self.limits.requests_per_minute}/min")

    def consume_quota(self, tenant_id: str, resource: str = "scans", amount: int = 1) -> int:
        key = (tenant_id, resource)
        used = self._quota.get(key, 0) + amount
        cap = self.limits.daily_scan_quota
        if used > cap:
            raise QuotaExceeded(f"tenant {tenant_id!r} exceeded daily {resource} quota ({cap})")
        self._quota[key] = used
        return used

    def quota_used(self, tenant_id: str, resource: str = "scans") -> int:
        return self._quota.get((tenant_id, resource), 0)


@dataclass
class ServiceIdentity:
    """A short-lived service identity — never an ambient long-lived credential."""

    name: str
    tenant_id: str | None
    issued_at: datetime
    expires_at: datetime
    scopes: tuple[str, ...] = ()

    def valid(self, now: datetime | None = None, *, scope: str | None = None) -> bool:
        now = now or _now()
        if now >= self.expires_at:
            return False
        return scope is None or scope in self.scopes


@dataclass
class BreakGlass:
    """An explicit, audited administrative override — time-limited and recorded."""

    operator: str
    reason: str
    expires_at: datetime
    audit: list = field(default_factory=list)

    def use(self, action: str, now: datetime | None = None) -> bool:
        now = now or _now()
        active = now < self.expires_at
        self.audit.append({"action": action, "at": now.isoformat(), "granted": active,
                           "operator": self.operator, "reason": self.reason})
        return active
