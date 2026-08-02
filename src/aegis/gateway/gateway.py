"""Scoped execution gateway (Master Prompt §core boundaries, network profiles).

The single outbound-network policy authority for target-facing tools. Every
request a worker or external adapter wants to make is authorised here first:

* **Network profile** — passive-provider / target-observation / target-mutation
  / private-oast — bounds *what class* of destination and method is allowed.
* **Signed scope** — target profiles may only reach hosts in the immutable
  signed scope; passive-provider may only reach configured intelligence
  providers; direct target traffic from a passive profile is denied.
* **DNS pinning** — the destination is resolved once and pinned; a later
  resolution that shares no address (DNS rebinding / change) is denied.
* **Private-IP (SSRF) denial** — a host resolving to an internal/link-local/
  loopback address is denied.
* **Redirect revalidation** — a redirect target is re-authorised; a redirect out
  of the profile/scope is denied.
* **Request budget** — a per-engagement cap; exhaustion denies further requests.
* **Network audit** — every allow/deny is recorded.

This is the testable interface + an in-process (fake) enforcement backend, per
the Phase 1 spec. The production backend must additionally enforce egress at the
network-namespace/container layer (proxy env vars are *not* enforcement); that is
a deployment concern layered beneath this policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable
from urllib.parse import urlsplit

from aegis.netgate import is_blocked_ip
from aegis.policy import ScopeGuard

Resolver = Callable[[str], list[str]]
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class NetworkProfile(str, Enum):
    PASSIVE_PROVIDER = "passive-provider"
    TARGET_OBSERVATION = "target-observation"
    TARGET_MUTATION = "target-mutation"
    PRIVATE_OAST = "private-oast"


class GatewayBlocked(Exception):
    def __init__(self, host: str, reason: str) -> None:
        self.host = host
        self.reason = reason
        super().__init__(f"gateway blocked {host!r}: {reason}")


@dataclass
class GatewayDecision:
    allowed: bool
    reason: str
    host: str = ""
    pinned_ip: str | None = None


@dataclass
class NetworkAuditEvent:
    method: str
    url: str
    host: str
    profile: str
    allowed: bool
    reason: str
    pinned_ip: str | None
    at: datetime


@dataclass
class GatewayConfig:
    profile: NetworkProfile
    scope: ScopeGuard | None = None                     # target profiles
    allowed_providers: list[str] = field(default_factory=list)  # passive-provider
    oast_host: str | None = None                        # private-oast
    allowed_methods: set[str] | None = None             # target-mutation (from reservation)
    request_budget: int | None = None
    block_private_ips: bool = True


def _host_of(url: str) -> str:
    candidate = url if "//" in url else f"//{url}"
    return (urlsplit(candidate).hostname or "").lower().rstrip(".")


def _default_resolver(host: str) -> list[str]:
    import socket

    return list({info[4][0] for info in socket.getaddrinfo(host, None)})


class ScopedExecutionGateway:
    def __init__(
        self,
        config: GatewayConfig,
        *,
        resolver: Resolver | None = None,
        on_audit: Callable[[NetworkAuditEvent], None] | None = None,
    ) -> None:
        self._config = config
        self._resolver = resolver or _default_resolver
        self._on_audit = on_audit
        self._pins: dict[str, set[str]] = {}
        self._requests_made = 0
        self._audit: list[NetworkAuditEvent] = []

    # -- public API --

    def authorize(self, method: str, url: str) -> GatewayDecision:
        """Authorise a request, consuming one unit of the request budget on allow."""
        return self._evaluate(method, url, consume=True)

    def check(self, method: str, url: str) -> GatewayDecision:
        """Authorise without consuming budget (dry run)."""
        return self._evaluate(method, url, consume=False)

    def require(self, method: str, url: str) -> GatewayDecision:
        decision = self.authorize(method, url)
        if not decision.allowed:
            raise GatewayBlocked(decision.host, decision.reason)
        return decision

    def check_redirect(self, method: str, location: str) -> GatewayDecision:
        """Re-authorise a redirect target (a new request that also consumes budget)."""
        return self.authorize(method, location)

    @property
    def requests_made(self) -> int:
        return self._requests_made

    def audit_events(self) -> list[NetworkAuditEvent]:
        return list(self._audit)

    # -- evaluation --

    def _record(self, decision: GatewayDecision, method: str, url: str) -> GatewayDecision:
        event = NetworkAuditEvent(
            method=method.upper(), url=url, host=decision.host, profile=self._config.profile.value,
            allowed=decision.allowed, reason=decision.reason, pinned_ip=decision.pinned_ip,
            at=datetime.now(timezone.utc),
        )
        self._audit.append(event)
        if self._on_audit is not None:
            self._on_audit(event)
        return decision

    def _evaluate(self, method: str, url: str, *, consume: bool) -> GatewayDecision:
        host = _host_of(url)

        if self._config.request_budget is not None and self._requests_made >= self._config.request_budget:
            return self._record(GatewayDecision(False, "request budget exhausted", host), method, url)
        if not host:
            return self._record(GatewayDecision(False, "request has no host", host), method, url)
        if not self._method_allowed(method):
            return self._record(GatewayDecision(False, f"method {method} not permitted for profile", host), method, url)

        allowed, reason = self._destination_allowed(host)
        if not allowed:
            return self._record(GatewayDecision(False, reason, host), method, url)

        try:
            resolved = set(self._resolver(host))
        except Exception as exc:  # fail closed on resolution failure
            return self._record(GatewayDecision(False, f"dns resolution failed: {exc}", host), method, url)
        if not resolved:
            return self._record(GatewayDecision(False, "host did not resolve", host), method, url)

        # The approved private OAST host is a legitimate internal destination, so
        # it is exempt from the private-IP block; everything else is not.
        is_oast = (
            self._config.profile == NetworkProfile.PRIVATE_OAST
            and self._config.oast_host is not None
            and host == self._config.oast_host.lower()
        )
        if self._config.block_private_ips and not is_oast:
            for ip in resolved:
                if is_blocked_ip(ip):
                    return self._record(GatewayDecision(False, f"resolves to a blocked/internal address ({ip})", host), method, url)

        pinned = self._pins.get(host)
        if pinned is None:
            self._pins[host] = resolved
            pinned_ip = next(iter(resolved), None)
        elif pinned.isdisjoint(resolved):
            return self._record(GatewayDecision(False, "DNS changed since pinning (possible rebinding)", host), method, url)
        else:
            pinned_ip = next(iter(pinned & resolved), None)

        if consume:
            self._requests_made += 1
        return self._record(GatewayDecision(True, "allowed", host, pinned_ip), method, url)

    def _method_allowed(self, method: str) -> bool:
        m = method.upper()
        if self._config.profile == NetworkProfile.TARGET_MUTATION:
            allowed = self._config.allowed_methods or SAFE_METHODS
            return m in {x.upper() for x in allowed}
        return m in SAFE_METHODS

    def _destination_allowed(self, host: str) -> tuple[bool, str]:
        profile = self._config.profile
        if profile == NetworkProfile.PASSIVE_PROVIDER:
            if ScopeGuard(self._config.allowed_providers).is_allowed(host):
                return True, ""
            return False, "host is not a configured passive provider (no direct target traffic)"
        if profile in (NetworkProfile.TARGET_OBSERVATION, NetworkProfile.TARGET_MUTATION):
            if self._config.scope is not None and self._config.scope.is_allowed(host):
                return True, ""
            return False, "destination is not in the signed scope"
        if profile == NetworkProfile.PRIVATE_OAST:
            if self._config.oast_host and host == self._config.oast_host.lower():
                return True, ""
            if self._config.scope is not None and self._config.scope.is_allowed(host):
                return True, ""
            return False, "not the private OAST host and not in scope"
        return False, "unknown network profile"
