"""Detector framework — the extensible "any bug class is a plug-in" core (§6).

A :class:`Detector` inspects a target through a **gated** HTTP client and emits
:class:`~aegis.model.Candidate` findings with reproducible evidence. Every
request goes through :meth:`DetectorContext.request`, which (a) enforces the
per-request policy gate (§17) and (b) rides the scope-enforcing transport
(:mod:`aegis.netgate`) — so a detector physically cannot reach out of scope.

New bug classes are added by writing a detector and registering it; nothing
else changes. High-value detectors ship in this package; the framework is the
answer to "handle any type of bug", not a promise that every class is covered.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Protocol, runtime_checkable
from urllib.parse import urljoin, urlsplit

import httpx

from aegis.model import Candidate, EvidenceBundle

# (action_class, url) -> allowed. The worker wires this to the policy gate.
GateFn = Callable[[str, str], bool]


class GateBlocked(Exception):
    """Raised when the per-request policy gate denies a request."""


@dataclass
class Identity:
    """A researcher-owned test account (never a real user)."""

    name: str
    headers: dict[str, str] = field(default_factory=dict)
    tenant: str | None = None       # the tenant this owned account belongs to


@dataclass
class DetectorContext:
    base_url: str
    client: httpx.Client  # a scope-enforcing (gated) client
    identities: list[Identity] = field(default_factory=list)
    action: str = "authenticated_testing"
    gate: GateFn | None = None
    params: dict = field(default_factory=dict)

    @property
    def host(self) -> str:
        return urlsplit(self.base_url).hostname or self.base_url

    def identity(self, name: str) -> Identity | None:
        for i in self.identities:
            if i.name == name:
                return i
        return None

    def _abs(self, url: str) -> str:
        if url.startswith("http://") or url.startswith("https://"):
            return url
        return urljoin(self.base_url.rstrip("/") + "/", url.lstrip("/"))

    def request(
        self,
        method: str,
        url: str,
        *,
        identity: Identity | None = None,
        headers: dict | None = None,
        **kwargs,
    ) -> httpx.Response:
        full = self._abs(url)
        if self.gate is not None and not self.gate(self.action, full):
            raise GateBlocked(full)
        merged = dict(headers or {})
        if identity is not None:
            merged.update(identity.headers)
        return self.client.request(method, full, headers=merged, **kwargs)

    def get(self, url: str, **kwargs) -> httpx.Response:
        return self.request("GET", url, **kwargs)


class DetectionResult:
    def __init__(self) -> None:
        self.candidates: list[Candidate] = []
        self.evidence: list[EvidenceBundle] = []
        self.sensitive_data_encountered: bool = False

    def add(self, candidate: Candidate, evidence: EvidenceBundle) -> None:
        self.candidates.append(candidate)
        self.evidence.append(evidence)

    def extend(self, other: "DetectionResult") -> None:
        self.candidates.extend(other.candidates)
        self.evidence.extend(other.evidence)
        self.sensitive_data_encountered = (
            self.sensitive_data_encountered or other.sensitive_data_encountered
        )


@runtime_checkable
class Detector(Protocol):
    name: str
    action: str
    cwe: str

    def applicable(self, ctx: DetectorContext) -> bool:
        ...

    def run(self, ctx: DetectorContext) -> DetectionResult:
        ...


class DetectorRegistry:
    def __init__(self) -> None:
        self._detectors: list[Detector] = []

    def register(self, detector: Detector) -> None:
        self._detectors.append(detector)

    def all(self) -> list[Detector]:
        return list(self._detectors)

    def applicable(self, ctx: DetectorContext) -> list[Detector]:
        return [d for d in self._detectors if d.applicable(ctx)]


def path_of(url: str) -> str:
    return urlsplit(url).path or "/"
