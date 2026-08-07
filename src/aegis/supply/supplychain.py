"""Supply-chain policy (Phase 5 §Isolation and supply chain).

The release-time controls that keep the distributed artifact trustworthy: generate
an SBOM and retain upstream license notices; pin images by digest (never a
floating tag); and block a release with a vulnerability above the configured
severity unless an operator has recorded a **time-limited** exception. Copyleft
licenses in the *distributed* set are surfaced, because the AGPL/GPL tools are
reimplemented clean-room and must never ship as vendored code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum

COPYLEFT_LICENSES = frozenset({"GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-3.0"})


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value) -> Severity:
        if isinstance(value, Severity):
            return value
        return cls[str(value).strip().upper()]


@dataclass(frozen=True)
class Component:
    name: str
    version: str
    license: str = ""
    digest: str = ""            # sha256 of the pinned artifact
    distributed: bool = False   # shipped in the release image


@dataclass(frozen=True)
class SBOM:
    components: tuple[Component, ...]

    def notices(self) -> list[dict]:
        """License notices to retain for every component that declares one."""
        return [{"name": c.name, "version": c.version, "license": c.license}
                for c in self.components if c.license]

    def copyleft_in_distribution(self) -> list[Component]:
        return [c for c in self.components if c.distributed and c.license in COPYLEFT_LICENSES]

    def to_dict(self) -> dict:
        return {"components": [vars(c) for c in self.components]}


def generate_sbom(components) -> SBOM:
    return SBOM(components=tuple(components))


# --- image pinning ---------------------------------------------------------

class UnpinnedImage(ValueError):
    pass


def verify_image_pin(image_ref: str) -> str:
    """Require a digest-pinned image reference; refuse a floating tag."""
    if "@sha256:" not in image_ref:
        raise UnpinnedImage(f"{image_ref!r} is not pinned by digest (use image@sha256:...)")
    digest = image_ref.split("@sha256:", 1)[1]
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest.lower()):
        raise UnpinnedImage(f"{image_ref!r} has an invalid sha256 digest")
    return digest


# --- severity policy -------------------------------------------------------

@dataclass(frozen=True)
class Vulnerability:
    vuln_id: str
    component: str
    severity: Severity


@dataclass(frozen=True)
class PolicyException:
    vuln_id: str
    reason: str
    operator: str
    expires_at: datetime

    def valid(self, now: datetime) -> bool:
        return now < self.expires_at


@dataclass
class PolicyResult:
    blocked: bool
    blocking: list = field(default_factory=list)     # vulns that block the release
    exempted: list = field(default_factory=list)     # blocked-but-exempted vulns


class SeverityPolicy:
    def __init__(self, max_allowed: Severity = Severity.MEDIUM) -> None:
        # Anything strictly above max_allowed blocks a release.
        self.max_allowed = Severity.parse(max_allowed)

    def evaluate(self, vulnerabilities, exceptions=(), *, now: datetime | None = None) -> PolicyResult:
        now = now or datetime.now(UTC)
        exempt = {e.vuln_id for e in exceptions if e.valid(now)}
        blocking, exempted = [], []
        for vuln in vulnerabilities:
            if Severity.parse(vuln.severity) <= self.max_allowed:
                continue
            if vuln.vuln_id in exempt:
                exempted.append(vuln)
            else:
                blocking.append(vuln)
        return PolicyResult(blocked=bool(blocking), blocking=blocking, exempted=exempted)
