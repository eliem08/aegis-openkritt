"""Cross-surface authorization and workflow correlation intelligence."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256


class CrossSurfaceKind(str, Enum):
    UPLOAD = "upload"
    MOBILE_BACKEND = "mobile_backend"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    GRPC = "grpc"
    DEEP_LINK = "deep_link"


class CrossSurfaceOutcome(str, Enum):
    VIOLATION = "violation"
    CORRELATION = "correlation"
    CONSISTENT = "consistent"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class CrossSurfaceObservation:
    observation_id: str
    kind: CrossSurfaceKind
    source: str
    target: str
    operation: str
    authorized_source: bool = False
    authorized_target: bool = False
    controlled_identities: bool = False
    control_succeeded: bool = False
    probe_succeeded: bool = False
    protected_marker_in_probe: bool = False
    protected_state_changed: bool = False
    synthetic_fixture: bool = False
    user_confirmation_observed: bool = True
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CrossSurfaceVerdict:
    verdict_id: str
    outcome: CrossSurfaceOutcome
    reason: str
    confidence: float
    observation: CrossSurfaceObservation
    evidence: tuple[str, ...]


class CrossSurfaceIntelligenceAgent:
    def evaluate(self, row: CrossSurfaceObservation) -> CrossSurfaceVerdict:
        verdict_id = "cross-surface:" + sha256(row.observation_id.encode()).hexdigest()[:20]
        if not row.authorized_source or not row.authorized_target:
            return CrossSurfaceVerdict(verdict_id, CrossSurfaceOutcome.INCONCLUSIVE,
                                       "both connected surfaces must be confirmed in scope",
                                       0.0, row, row.evidence)
        if row.kind is CrossSurfaceKind.MOBILE_BACKEND:
            if not row.evidence:
                return CrossSurfaceVerdict(verdict_id, CrossSurfaceOutcome.INCONCLUSIVE,
                                           "mobile/backend correlation requires callsite evidence",
                                           0.0, row, row.evidence)
            return CrossSurfaceVerdict(verdict_id, CrossSurfaceOutcome.CORRELATION,
                                       "authorized mobile callsite maps to an authorized backend operation",
                                       0.8, row, row.evidence)
        if not row.synthetic_fixture or not row.controlled_identities:
            return CrossSurfaceVerdict(verdict_id, CrossSurfaceOutcome.INCONCLUSIVE,
                                       "active differential requires controlled identities and fixture",
                                       0.0, row, row.evidence)
        if not row.control_succeeded:
            return CrossSurfaceVerdict(verdict_id, CrossSurfaceOutcome.INCONCLUSIVE,
                                       "allowed control did not establish baseline reachability",
                                       0.0, row, row.evidence)
        deep_link_violation = (
            row.kind is CrossSurfaceKind.DEEP_LINK and row.probe_succeeded
            and row.protected_state_changed and not row.user_confirmation_observed
        )
        if row.kind is CrossSurfaceKind.DEEP_LINK:
            violation = deep_link_violation or (
                row.probe_succeeded and row.protected_marker_in_probe
            )
        else:
            violation = row.probe_succeeded and (
                row.protected_marker_in_probe or row.protected_state_changed
            )
        if violation:
            return CrossSurfaceVerdict(verdict_id, CrossSurfaceOutcome.VIOLATION,
                                       "cross-surface probe exposed a protected marker or state effect",
                                       0.96, row, row.evidence)
        if not row.probe_succeeded and not row.protected_marker_in_probe:
            return CrossSurfaceVerdict(verdict_id, CrossSurfaceOutcome.CONSISTENT,
                                       "cross-surface negative control was denied without protected effect",
                                       0.88, row, row.evidence)
        return CrossSurfaceVerdict(verdict_id, CrossSurfaceOutcome.INCONCLUSIVE,
                                   "response lacks a protected marker or state oracle", 0.0,
                                   row, row.evidence)


__all__ = [
    "CrossSurfaceIntelligenceAgent", "CrossSurfaceKind", "CrossSurfaceObservation",
    "CrossSurfaceOutcome", "CrossSurfaceVerdict",
]
