"""Operator-loaded scope allowlist with a hard, fail-closed refusal path.

Touching an out-of-scope host is the mistake that gets a researcher banned, so this
guard is written to be boring and strict:

* Nothing is in scope unless an allowlist entry says so. An empty allowlist refuses
  everything; there is no permissive default and no "allow all" entry.
* An explicit ``out_of_scope`` entry always wins over an ``in_scope`` match, so a
  program that carves ``admin.example.com`` out of ``*.example.com`` is honored.
* A destination that cannot be parsed is refused, never passed through.
* CIDR entries match only IP-literal destinations. A hostname is never silently
  resolved and then range-matched — DNS is attacker-influenced, and a resolver
  answer is not authorization.

It complements ``aegis.policy.scope.ScopeGuard`` (the in-process mirror of the
network-layer allowlist) by adding the file format, CIDR ranges, explicit
exclusions, and the CIDR-expansion budget the asset lanes need.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

from aegis.policy.scope import normalize_host

#: Refuse to expand a range larger than this into individual hosts. A /16 sweep is
#: not "one asset", and an accidental /8 in a scope file must fail loudly.
MAX_CIDR_HOSTS = 1024


class OutOfScopeError(PermissionError):
    """A technique attempted to touch a destination the allowlist does not cover."""

    def __init__(self, destination: str, reason: str) -> None:
        super().__init__(f"refusing out-of-scope destination {destination!r}: {reason}")
        self.destination = destination
        self.reason = reason


class ScopeFileError(ValueError):
    """The operator's scope file is missing, malformed, or empty."""


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    allowed: bool
    destination: str
    host: str
    matched_rule: str
    reason: str

    def document(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ScopeAllowlist:
    """An immutable in/out-of-scope decision table loaded from an operator file."""

    program: str
    hosts: frozenset[str] = frozenset()
    wildcards: frozenset[str] = frozenset()
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    excluded_hosts: frozenset[str] = frozenset()
    excluded_wildcards: frozenset[str] = frozenset()
    excluded_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    source_path: str = ""
    notes: Mapping[str, Any] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return len(self.hosts) + len(self.wildcards) + len(self.networks)

    def evaluate(self, destination: str) -> ScopeDecision:
        """Decide a destination. Never raises — the refusal is the return value."""
        raw = (destination or "").strip()
        if not raw:
            return ScopeDecision(False, destination, "", "", "empty destination")
        try:
            host = _host_of(raw)
        except ValueError as exc:
            return ScopeDecision(False, destination, "", "", str(exc))

        address = _as_ip(host)
        excluded = self._match(host, address, self.excluded_hosts,
                               self.excluded_wildcards, self.excluded_networks)
        if excluded:
            return ScopeDecision(
                False, destination, host, excluded,
                "explicitly listed out of scope; exclusions override inclusions",
            )
        matched = self._match(host, address, self.hosts, self.wildcards, self.networks)
        if matched:
            return ScopeDecision(True, destination, host, matched, "allowlist match")
        return ScopeDecision(
            False, destination, host, "",
            "no allowlist entry covers this destination (fail closed)",
        )

    def require(self, destination: str) -> ScopeDecision:
        """Return the decision, or raise ``OutOfScopeError`` when it refuses."""
        decision = self.evaluate(destination)
        if not decision.allowed:
            raise OutOfScopeError(destination, decision.reason)
        return decision

    def is_allowed(self, destination: str) -> bool:
        return self.evaluate(destination).allowed

    def expand_network(self, cidr: str) -> tuple[str, ...]:
        """Expand an in-scope CIDR into individual host addresses, budget-capped."""
        network = ipaddress.ip_network(cidr.strip(), strict=False)
        if not any(network.subnet_of(item) for item in self.networks
                   if item.version == network.version):
            raise OutOfScopeError(cidr, "CIDR is not contained in an allowlisted range")
        total = network.num_addresses
        if total > MAX_CIDR_HOSTS:
            raise OutOfScopeError(
                cidr,
                f"range holds {total} addresses which exceeds the {MAX_CIDR_HOSTS} "
                "expansion budget; narrow the target before sweeping",
            )
        return tuple(str(item) for item in _iter_hosts(network))

    def document(self) -> dict[str, Any]:
        return {
            "program": self.program,
            "source_path": self.source_path,
            "in_scope": {
                "hosts": sorted(self.hosts),
                "wildcards": sorted(f"*.{item}" for item in self.wildcards),
                "networks": [str(item) for item in self.networks],
            },
            "out_of_scope": {
                "hosts": sorted(self.excluded_hosts),
                "wildcards": sorted(f"*.{item}" for item in self.excluded_wildcards),
                "networks": [str(item) for item in self.excluded_networks],
            },
            "entry_count": self.size,
            "notes": dict(self.notes),
        }

    @staticmethod
    def _match(
        host: str,
        address: ipaddress.IPv4Address | ipaddress.IPv6Address | None,
        hosts: frozenset[str],
        wildcards: frozenset[str],
        networks: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network],
    ) -> str:
        if host in hosts:
            return host
        for suffix in wildcards:
            # "*.example.com" covers subdomains at any depth but not the apex,
            # which must be listed separately — matching ScopeGuard's semantics.
            if host.endswith("." + suffix):
                return f"*.{suffix}"
        if address is not None:
            for network in networks:
                if address.version == network.version and address in network:
                    return str(network)
        return ""


def _as_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def _host_of(destination: str) -> str:
    """Extract the host, tolerating a bare IPv6 literal that urlsplit cannot parse.

    ``normalize_host`` builds a ``//host`` URL, and ``//2001:db8::1`` parses as host
    ``2001`` with a bad port. An unbracketed IPv6 literal is common in scope files,
    so it is recognized before the URL path is attempted — never after, which would
    let a malformed destination through.
    """
    raw = (destination or "").strip()
    if _as_ip(raw) is not None:
        return raw.strip("[]").lower()
    return normalize_host(raw)


def _iter_hosts(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> Iterator[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    if network.prefixlen >= network.max_prefixlen - 1:
        return iter(network)
    return network.hosts()


def _classify(entry: str) -> tuple[str, Any]:
    """Split one raw scope line into ``(kind, value)`` or raise ``ScopeFileError``."""
    value = (entry or "").strip().lower().rstrip(".")
    if not value or value.startswith("#"):
        return "", None
    if value in {"*", "*.*", "any", "all"}:
        raise ScopeFileError(
            f"catch-all scope entry {entry!r} is refused; list real hosts, wildcards, or CIDRs"
        )
    if value.startswith("*."):
        suffix = value[2:]
        if not suffix or "*" in suffix:
            raise ScopeFileError(f"malformed wildcard scope entry: {entry!r}")
        return "wildcard", suffix
    if "/" in value and "//" not in value:
        try:
            return "network", ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ScopeFileError(f"malformed CIDR scope entry {entry!r}: {exc}") from exc
    try:
        return "host", _host_of(value)
    except ValueError as exc:
        raise ScopeFileError(f"malformed host scope entry {entry!r}: {exc}") from exc


def build_allowlist(
    *,
    program: str,
    in_scope: Iterable[str],
    out_of_scope: Iterable[str] = (),
    source_path: str = "",
    notes: Mapping[str, Any] | None = None,
) -> ScopeAllowlist:
    """Construct an allowlist from raw entries, refusing an empty in-scope set."""
    hosts: set[str] = set()
    wildcards: set[str] = set()
    networks: list[Any] = []
    excluded_hosts: set[str] = set()
    excluded_wildcards: set[str] = set()
    excluded_networks: list[Any] = []
    for entry in in_scope:
        kind, value = _classify(entry)
        if kind == "host":
            hosts.add(value)
        elif kind == "wildcard":
            wildcards.add(value)
        elif kind == "network":
            networks.append(value)
    for entry in out_of_scope:
        kind, value = _classify(entry)
        if kind == "host":
            excluded_hosts.add(value)
        elif kind == "wildcard":
            excluded_wildcards.add(value)
        elif kind == "network":
            excluded_networks.append(value)
    if not (hosts or wildcards or networks):
        raise ScopeFileError(
            "scope allowlist has no in-scope entries; an empty allowlist would refuse "
            "everything, which is almost certainly a mistake in the scope file"
        )
    return ScopeAllowlist(
        program=program or "unnamed-program",
        hosts=frozenset(hosts), wildcards=frozenset(wildcards), networks=tuple(networks),
        excluded_hosts=frozenset(excluded_hosts),
        excluded_wildcards=frozenset(excluded_wildcards),
        excluded_networks=tuple(excluded_networks),
        source_path=source_path, notes=dict(notes or {}),
    )


def load_allowlist(path: str | Path) -> ScopeAllowlist:
    """Load an operator scope file.

    JSON shape::

        {
          "program": "acme-bbp",
          "in_scope": ["*.acme.com", "api.acme.io", "203.0.113.0/24"],
          "out_of_scope": ["admin.acme.com"],
          "notes": {"engagement_url": "https://..."}
        }

    A newline-delimited text file is also accepted, where a leading ``!`` marks an
    out-of-scope entry and ``#`` starts a comment.
    """
    source = Path(path)
    if not source.is_file():
        raise ScopeFileError(f"scope file does not exist: {source}")
    raw = source.read_text(encoding="utf-8").strip()
    if not raw:
        raise ScopeFileError(f"scope file is empty: {source}")

    if raw.startswith("{"):
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ScopeFileError(f"scope file is not valid JSON: {exc}") from exc
        if not isinstance(document, dict):
            raise ScopeFileError("scope file JSON must be an object")
        return build_allowlist(
            program=str(document.get("program") or source.stem),
            in_scope=[str(item) for item in document.get("in_scope") or ()],
            out_of_scope=[str(item) for item in document.get("out_of_scope") or ()],
            source_path=str(source),
            notes=document.get("notes") if isinstance(document.get("notes"), dict) else {},
        )

    included: list[str] = []
    excluded: list[str] = []
    for line in raw.splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        if entry.startswith("!"):
            excluded.append(entry[1:].strip())
        else:
            included.append(entry)
    return build_allowlist(
        program=source.stem, in_scope=included, out_of_scope=excluded,
        source_path=str(source),
    )


__all__ = [
    "MAX_CIDR_HOSTS",
    "OutOfScopeError",
    "ScopeAllowlist",
    "ScopeDecision",
    "ScopeFileError",
    "build_allowlist",
    "load_allowlist",
]
