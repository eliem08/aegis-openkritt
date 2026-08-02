"""Outbound scope enforcement — the network-layer control (Master Prompt §2).

The operating prompt is explicit: *scope is enforced by the network layer, not
by the agent.* This module is that layer for HTTP: a custom httpx transport that
inspects **every** request — the initial one, **every redirect hop**, and the
**DNS-resolved IP** — and refuses anything outside the signed scope or pointing
at a private/internal address (SSRF guard).

Because it sits at the transport, it catches requests a worker makes internally
that a per-action gate would miss (§17), and redirects that would otherwise
escape scope. It is defense-in-depth beside the deterministic policy gate, and
it fails closed: if a host can't be resolved or parsed, the request is blocked.

Known limitation: this resolves the host to check the IP, but httpx resolves
again at connect time, so it is not fully DNS-rebinding-proof (that needs
connection-level IP pinning). It still blocks the common cases: out-of-scope
hosts, redirects out of scope, and hosts that resolve to internal ranges.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Callable

import httpx

from aegis.policy import ScopeGuard

Resolver = Callable[[str], list[str]]
OnBlock = Callable[[str, str], None]


class ScopeViolation(Exception):
    """Raised when a request is blocked by scope/SSRF enforcement."""

    def __init__(self, host: str, reason: str) -> None:
        self.host = host
        self.reason = reason
        super().__init__(f"blocked request to {host!r}: {reason}")


def is_blocked_ip(ip_str: str) -> bool:
    """True for addresses a scan must never reach (fail closed on parse error)."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _default_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None)
    return list({info[4][0] for info in infos})


class ScopeEnforcingTransport(httpx.BaseTransport):
    def __init__(
        self,
        inner: httpx.BaseTransport,
        scope: ScopeGuard,
        *,
        block_private_ips: bool = True,
        resolver: Resolver | None = None,
        on_block: OnBlock | None = None,
    ) -> None:
        self._inner = inner
        self._scope = scope
        self._block_private = block_private_ips
        self._resolver = resolver or _default_resolver
        self._on_block = on_block

    def _block(self, host: str, reason: str) -> None:
        if self._on_block is not None:
            self._on_block(host, reason)
        raise ScopeViolation(host, reason)

    def _resolved_ips(self, host: str) -> list[str]:
        try:
            ipaddress.ip_address(host)
            return [host]  # already a literal IP
        except ValueError:
            pass
        try:
            return self._resolver(host)
        except Exception as exc:  # fail closed on resolution failure
            self._block(host, f"dns resolution failed: {exc}")
            return []  # unreachable; _block raises

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if not host:
            self._block(request.url.raw_path.decode("ascii", "replace"), "request has no host")

        if not self._scope.is_allowed(host):
            self._block(host, "destination is not in the signed scope")

        if self._block_private:
            for ip in self._resolved_ips(host):
                if is_blocked_ip(ip):
                    self._block(host, f"resolves to a blocked/internal address ({ip})")

        return self._inner.handle_request(request)

    def close(self) -> None:
        self._inner.close()


def build_gated_client(
    scope: ScopeGuard | list[str],
    *,
    inner: httpx.BaseTransport | None = None,
    block_private_ips: bool = True,
    resolver: Resolver | None = None,
    on_block: OnBlock | None = None,
    follow_redirects: bool = True,
    **client_kwargs,
) -> httpx.Client:
    """An httpx.Client whose every request is scope-enforced.

    ``follow_redirects`` defaults to True *on purpose*: redirects are followed so
    that each hop is re-checked against scope (a redirect out of scope is
    blocked). Pass a ``ScopeGuard`` or a list of allowlist entries.
    """
    guard = scope if isinstance(scope, ScopeGuard) else ScopeGuard(scope)
    inner_transport = inner or httpx.HTTPTransport()
    transport = ScopeEnforcingTransport(
        inner_transport,
        guard,
        block_private_ips=block_private_ips,
        resolver=resolver,
        on_block=on_block,
    )
    return httpx.Client(transport=transport, follow_redirects=follow_redirects, **client_kwargs)
