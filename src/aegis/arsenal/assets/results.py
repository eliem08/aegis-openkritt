"""Result types shared by every asset lane.

A technique reports what it *actually did*, using the arsenal's existing
``ArsenalCoverageState`` vocabulary so a hunt report and the capability audit
describe outcomes in the same words. The important property is that a technique
which could not run says so explicitly — ``UNAVAILABLE`` with a reason, never an
empty observation list that reads like a clean result.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Mapping, Sequence

from ..models import ArsenalCoverageState

#: Severity vocabulary, deliberately the same words the report lane already uses.
SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True, slots=True)
class Observation:
    """One factual thing a technique saw. Not yet a finding, and never a claim.

    ``guarded_sibling`` carries the contrast evidence the operator's method relies
    on: the comparable code path or endpoint that *does* enforce the control. An
    observation without one is weaker and is scored as such downstream.
    """

    technique_id: str
    title: str
    severity: str
    subject: str
    evidence: Mapping[str, Any] = field(default_factory=dict)
    guarded_sibling: str = ""
    weakness: str = ""
    confidence: str = "unverified"
    recommendation: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}, got {self.severity!r}")

    def document(self) -> dict[str, Any]:
        value = asdict(self)
        value["evidence"] = dict(self.evidence)
        return value


@dataclass(frozen=True, slots=True)
class TechniqueResult:
    """The outcome of one technique against one asset."""

    technique_id: str
    asset: str
    state: ArsenalCoverageState
    observations: tuple[Observation, ...] = ()
    reason: str = ""
    tool: str = ""
    tool_version: str = ""
    requests_made: int = 0
    started_at: str = ""
    finished_at: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def executed(self) -> bool:
        return self.state in {
            ArsenalCoverageState.EXECUTED_PASS, ArsenalCoverageState.EXECUTED_FINDING,
        }

    def document(self) -> dict[str, Any]:
        value = asdict(self)
        value["state"] = self.state.value
        value["observations"] = [item.document() for item in self.observations]
        value["metadata"] = dict(self.metadata)
        return value


def now() -> str:
    return datetime.now(UTC).isoformat()


def executed(
    technique_id: str,
    asset: str,
    observations: Sequence[Observation] = (),
    *,
    reason: str = "",
    tool: str = "",
    tool_version: str = "",
    requests_made: int = 0,
    started_at: str = "",
    metadata: Mapping[str, Any] | None = None,
) -> TechniqueResult:
    """A technique that ran. Findings present promote the state, honestly."""
    state = (
        ArsenalCoverageState.EXECUTED_FINDING if observations
        else ArsenalCoverageState.EXECUTED_PASS
    )
    return TechniqueResult(
        technique_id, asset, state, tuple(observations), reason, tool, tool_version,
        requests_made, started_at or now(), now(), dict(metadata or {}),
    )


def unavailable(
    technique_id: str, asset: str, reason: str, *, tool: str = "",
    metadata: Mapping[str, Any] | None = None,
) -> TechniqueResult:
    """A technique that could not run — missing binary, unreachable target, bad input."""
    return TechniqueResult(
        technique_id, asset, ArsenalCoverageState.UNAVAILABLE, (), reason, tool,
        started_at=now(), finished_at=now(), metadata=dict(metadata or {}),
    )


def waiting(
    technique_id: str, asset: str, reason: str, *,
    metadata: Mapping[str, Any] | None = None,
) -> TechniqueResult:
    """A technique whose prerequisite (spec, artifact, second identity) is absent."""
    return TechniqueResult(
        technique_id, asset, ArsenalCoverageState.WAITING_FOR_PREREQUISITE, (), reason,
        started_at=now(), finished_at=now(), metadata=dict(metadata or {}),
    )


def denied(
    technique_id: str, asset: str, reason: str, *,
    metadata: Mapping[str, Any] | None = None,
) -> TechniqueResult:
    """A technique refused by scope, the read-only default, or the request budget."""
    return TechniqueResult(
        technique_id, asset, ArsenalCoverageState.DENIED_BY_POLICY, (), reason,
        started_at=now(), finished_at=now(), metadata=dict(metadata or {}),
    )


def not_implemented(
    technique_id: str, asset: str, reason: str, *,
    metadata: Mapping[str, Any] | None = None,
) -> TechniqueResult:
    """A technique registered but deliberately not yet built. Never silently empty."""
    return TechniqueResult(
        technique_id, asset, ArsenalCoverageState.NOT_IMPLEMENTED, (), reason,
        started_at=now(), finished_at=now(), metadata=dict(metadata or {}),
    )


def deduplicate(observations: Sequence[Observation]) -> tuple[Observation, ...]:
    """Collapse observations that describe the same weakness on the same subject.

    De-dupe is part of the operator's method: one report per distinct weakness, not
    one per scanner that noticed it. The first occurrence wins so the richer
    evidence gathered earliest in a lane is preserved.
    """
    seen: dict[tuple[str, str, str], Observation] = {}
    for item in observations:
        key = (item.subject.lower(), (item.weakness or item.title).lower(), item.severity)
        seen.setdefault(key, item)
    return tuple(seen.values())


__all__ = [
    "Observation",
    "SEVERITIES",
    "TechniqueResult",
    "denied",
    "deduplicate",
    "executed",
    "not_implemented",
    "now",
    "unavailable",
    "waiting",
]
