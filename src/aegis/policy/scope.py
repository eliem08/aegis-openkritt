"""Scope enforcement — the allowlist mirror (Master Prompt §2).

The authoritative scope control is the *network layer*: any request to a
non-allowlisted destination must be impossible at the proxy. This module is the
in-process mirror of that allowlist — defense in depth. If this guard and the
network layer ever disagree, that is a ``SCOPE_ESCAPE`` incident.

Matching is deliberately strict:
  * hosts are compared case-insensitively after stripping scheme / port / path,
  * an exact host match is required by default,
  * a wildcard entry ``*.example.test`` matches immediate-or-deeper subdomains
    but NOT the apex ``example.test`` (which must be listed explicitly),
  * IP literals only match if the exact IP is listed (no CIDR guessing here).
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit


def normalize_host(destination: str) -> str:
    """Extract a bare, lowercased host from a URL, ``host:port``, or host.

    Raises ``ValueError`` if no host can be determined — callers must treat an
    unparseable destination as out of scope, never as a pass.
    """
    if destination is None:
        raise ValueError("destination is None")
    raw = destination.strip()
    if not raw:
        raise ValueError("empty destination")

    # If it looks like a URL, let urlsplit find the host. Otherwise synthesise a
    # scheme so urlsplit treats the whole thing as netloc rather than path.
    candidate = raw if "//" in raw else f"//{raw}"
    parts = urlsplit(candidate)
    host = parts.hostname
    if not host:
        raise ValueError(f"could not extract host from {destination!r}")
    return host.lower().rstrip(".")


@dataclass(frozen=True)
class ScopeResult:
    in_scope: bool
    host: str
    matched_rule: str | None = None
    reason: str = ""


class ScopeGuard:
    """Decides whether a destination host is inside the approved allowlist."""

    def __init__(self, allowlist: list[str] | None = None) -> None:
        self._exact: set[str] = set()
        self._wildcards: set[str] = set()  # stored as the suffix after "*."
        for entry in allowlist or []:
            self.add(entry)

    def add(self, entry: str) -> None:
        entry = entry.strip().lower().rstrip(".")
        if not entry:
            return
        if entry.startswith("*."):
            self._wildcards.add(entry[2:])
        else:
            # Exact authorization targets may be repository/API URLs while
            # enforcement compares destinations at the host boundary. Apply
            # the same normalization on both sides. Invalid allowlist entries
            # are ignored and therefore remain fail closed.
            try:
                self._exact.add(normalize_host(entry))
            except ValueError:
                return

    @classmethod
    def from_authorization(cls, targets: list[str]) -> ScopeGuard:
        return cls(list(targets))

    def evaluate(self, destination: str) -> ScopeResult:
        try:
            host = normalize_host(destination)
        except ValueError as exc:
            return ScopeResult(False, host="", matched_rule=None, reason=str(exc))

        if host in self._exact:
            return ScopeResult(True, host, matched_rule=host, reason="exact match")

        for suffix in self._wildcards:
            # "*.example.test" matches "a.example.test" and "a.b.example.test",
            # but not the apex "example.test".
            if host.endswith("." + suffix):
                return ScopeResult(True, host, matched_rule=f"*.{suffix}", reason="wildcard match")

        return ScopeResult(False, host, matched_rule=None, reason="host not in allowlist")

    def is_allowed(self, destination: str) -> bool:
        return self.evaluate(destination).in_scope

    @property
    def size(self) -> int:
        return len(self._exact) + len(self._wildcards)
