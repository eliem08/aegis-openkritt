"""Evidence-first identity, lifecycle, and error-state differential intelligence.

This module only evaluates observations produced by an authorized bounded executor.  It never
creates identities, sends requests, or treats an HTTP status alone as proof of authorization.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from hashlib import sha256
from typing import Iterable


class ExpectedAccess(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    UNKNOWN = "unknown"


class DifferentialOutcome(str, Enum):
    CONSISTENT = "consistent"
    VIOLATION = "violation"
    INCONCLUSIVE = "inconclusive"


class StateVerificationOutcome(str, Enum):
    CLEAN_ROLLBACK = "clean_rollback"
    HIDDEN_COMMIT = "hidden_commit"
    PARTIAL_COMMIT = "partial_commit"
    COMPLETE_COMMIT = "complete_commit"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class ControlledPrincipal:
    principal_id: str
    role: str
    tenant: str
    controlled: bool = False
    authorization_evidence: tuple[str, ...] = ()

    @property
    def eligible(self) -> bool:
        return self.controlled and bool(self.authorization_evidence)


@dataclass(frozen=True, slots=True)
class SyntheticResource:
    resource_id: str
    owner_id: str
    tenant: str
    canary: str
    synthetic: bool = True


@dataclass(frozen=True, slots=True)
class AccessObservation:
    principal: ControlledPrincipal
    resource: SyntheticResource
    operation: str
    status_code: int | None
    response_digest: str = ""
    returned_markers: tuple[str, ...] = ()
    before_state_digest: str = ""
    after_state_digest: str = ""
    side_effects: tuple[str, ...] = ()
    timed_out: bool = False
    correlation_id: str = ""
    evidence: tuple[str, ...] = ()
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class AuthorizationRule:
    operation: str
    principal_id: str
    resource_id: str
    expected: ExpectedAccess
    evidence: tuple[str, ...] = ()


class AuthorizationMatrix:
    """Explicit policy expectations; absence is UNKNOWN, never an inferred deny."""

    def __init__(self, rules: Iterable[AuthorizationRule] = ()) -> None:
        self._rules = {
            (rule.operation, rule.principal_id, rule.resource_id): rule for rule in rules
        }

    def expectation(self, observation: AccessObservation) -> AuthorizationRule:
        return self._rules.get(
            (observation.operation, observation.principal.principal_id,
             observation.resource.resource_id),
            AuthorizationRule(
                observation.operation, observation.principal.principal_id,
                observation.resource.resource_id, ExpectedAccess.UNKNOWN,
            ),
        )


@dataclass(frozen=True, slots=True)
class DifferentialVerdict:
    verdict_id: str
    outcome: DifferentialOutcome
    dimension: str
    reason: str
    confidence: float
    control: AccessObservation
    probe: AccessObservation
    evidence: tuple[str, ...]


class IdentityDifferentialOracle:
    """Compare an owner/allowed control with a distinct, explicitly controlled probe."""

    def evaluate(
        self,
        control: AccessObservation,
        probe: AccessObservation,
        matrix: AuthorizationMatrix,
    ) -> DifferentialVerdict:
        material = (control.correlation_id, probe.correlation_id, probe.operation,
                    probe.principal.principal_id, probe.resource.resource_id)
        verdict_id = "identity-verdict:" + sha256("\x1f".join(material).encode()).hexdigest()[:20]
        dimension = self._dimension(control, probe)
        evidence = tuple(dict.fromkeys((*control.evidence, *probe.evidence)))
        if control.principal.principal_id == probe.principal.principal_id:
            return DifferentialVerdict(verdict_id, DifferentialOutcome.INCONCLUSIVE, dimension,
                                       "probe is not a distinct identity", 0.0,
                                       control, probe, evidence)
        if not control.principal.eligible or not probe.principal.eligible:
            return DifferentialVerdict(verdict_id, DifferentialOutcome.INCONCLUSIVE, dimension,
                                       "both identities require explicit control evidence", 0.0,
                                       control, probe, evidence)
        if not probe.resource.synthetic or not probe.resource.canary:
            return DifferentialVerdict(verdict_id, DifferentialOutcome.INCONCLUSIVE, dimension,
                                       "resource is not a marked synthetic fixture", 0.0,
                                       control, probe, evidence)
        expectation = matrix.expectation(probe)
        if expectation.expected is ExpectedAccess.UNKNOWN or not expectation.evidence:
            return DifferentialVerdict(verdict_id, DifferentialOutcome.INCONCLUSIVE, dimension,
                                       "expected policy is unknown or unsupported", 0.0,
                                       control, probe, evidence)
        if control.status_code is None or not (200 <= control.status_code < 300):
            return DifferentialVerdict(verdict_id, DifferentialOutcome.INCONCLUSIVE, dimension,
                                       "allowed control did not establish resource accessibility", 0.0,
                                       control, probe, evidence)
        if expectation.expected is ExpectedAccess.ALLOW:
            consistent = probe.status_code is not None and 200 <= probe.status_code < 300
            outcome = DifferentialOutcome.CONSISTENT if consistent else DifferentialOutcome.VIOLATION
            return DifferentialVerdict(
                verdict_id, outcome, dimension,
                "explicitly allowed probe succeeded" if consistent else
                "explicitly allowed probe was denied", 0.8, control, probe,
                tuple(dict.fromkeys((*evidence, *expectation.evidence))),
            )
        marker_exposed = probe.resource.canary in probe.returned_markers
        state_changed = bool(
            probe.before_state_digest and probe.after_state_digest
            and probe.before_state_digest != probe.after_state_digest
        )
        effect_observed = bool(probe.side_effects)
        violated = marker_exposed or state_changed or effect_observed
        if violated:
            reason = "denied identity observed owner canary or protected state change"
            outcome = DifferentialOutcome.VIOLATION
            confidence = 0.97 if marker_exposed else 0.9
        elif probe.status_code in {401, 403, 404}:
            reason = "denied identity was rejected with no protected effect"
            outcome = DifferentialOutcome.CONSISTENT
            confidence = 0.9
        else:
            reason = "status alone does not prove allow or deny without a canary or state effect"
            outcome = DifferentialOutcome.INCONCLUSIVE
            confidence = 0.0
        return DifferentialVerdict(
            verdict_id, outcome, dimension, reason, confidence, control, probe,
            tuple(dict.fromkeys((*evidence, *expectation.evidence))),
        )

    @staticmethod
    def _dimension(control: AccessObservation, probe: AccessObservation) -> str:
        if control.principal.tenant != probe.principal.tenant:
            return "tenant"
        if control.principal.role != probe.principal.role:
            return "role"
        return "account"


@dataclass(frozen=True, slots=True)
class StateVerification:
    verification_id: str
    outcome: StateVerificationOutcome
    reason: str
    confidence: float
    observation: AccessObservation
    evidence: tuple[str, ...]


class ErrorStateVerifier:
    """Verify rollback/commit behavior after errors, timeouts, and successful compound writes."""

    def verify(
        self,
        observation: AccessObservation,
        *,
        expected_effects: Iterable[str] = (),
    ) -> StateVerification:
        verification_id = "state-verification:" + sha256(
            f"{observation.correlation_id}\x1f{observation.resource.resource_id}".encode()
        ).hexdigest()[:20]
        evidence = tuple(observation.evidence)
        if not observation.resource.synthetic:
            return StateVerification(verification_id, StateVerificationOutcome.INCONCLUSIVE,
                                     "state verification requires a synthetic resource", 0.0,
                                     observation, evidence)
        if not observation.before_state_digest or not observation.after_state_digest:
            return StateVerification(verification_id, StateVerificationOutcome.INCONCLUSIVE,
                                     "before and after state readback are required", 0.0,
                                     observation, evidence)
        expected = set(expected_effects)
        observed = set(observation.side_effects)
        changed = observation.before_state_digest != observation.after_state_digest
        is_error = observation.timed_out or observation.status_code is None or observation.status_code >= 400
        if is_error:
            if not changed and not observed:
                return StateVerification(verification_id, StateVerificationOutcome.CLEAN_ROLLBACK,
                                         "error path preserved the pre-operation state", 0.95,
                                         observation, evidence)
            outcome = (StateVerificationOutcome.PARTIAL_COMMIT
                       if expected and observed != expected
                       else StateVerificationOutcome.HIDDEN_COMMIT)
            return StateVerification(verification_id, outcome,
                                     "error or timeout returned after a persistent state change", 0.95,
                                     observation, evidence)
        if expected and observed != expected:
            return StateVerification(verification_id, StateVerificationOutcome.PARTIAL_COMMIT,
                                     "successful compound operation committed only a subset of effects",
                                     0.92, observation, evidence)
        if changed or observed:
            return StateVerification(verification_id, StateVerificationOutcome.COMPLETE_COMMIT,
                                     "expected state change was observed", 0.9,
                                     observation, evidence)
        return StateVerification(verification_id, StateVerificationOutcome.INCONCLUSIVE,
                                 "successful response had no verifiable state effect", 0.0,
                                 observation, evidence)


@dataclass(frozen=True, slots=True)
class LifecycleTransitionRule:
    operation: str
    from_state: str
    to_state: str
    allowed: bool
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class LifecycleHypothesis:
    operation: str
    from_state: str
    to_state: str
    reason: str
    confidence: float
    evidence: tuple[str, ...]


class LifecycleStateAgent:
    """Select evidence-backed negative transitions without Cartesian state explosion."""

    def hypotheses(
        self,
        rules: Iterable[LifecycleTransitionRule],
        *,
        observed_states: Iterable[str],
    ) -> tuple[LifecycleHypothesis, ...]:
        states = set(observed_states)
        rows = []
        for rule in rules:
            if rule.allowed or not rule.evidence:
                continue
            if rule.from_state not in states or rule.to_state not in states:
                continue
            rows.append(LifecycleHypothesis(
                rule.operation, rule.from_state, rule.to_state,
                "explicitly forbidden transition is reachable from observed states",
                0.75, rule.evidence,
            ))
        return tuple(sorted(rows, key=lambda item: (item.operation, item.from_state, item.to_state)))


__all__ = [
    "AccessObservation", "AuthorizationMatrix", "AuthorizationRule",
    "ControlledPrincipal", "DifferentialOutcome", "DifferentialVerdict",
    "ErrorStateVerifier", "ExpectedAccess", "IdentityDifferentialOracle",
    "LifecycleHypothesis", "LifecycleStateAgent", "LifecycleTransitionRule",
    "StateVerification", "StateVerificationOutcome", "SyntheticResource",
]
