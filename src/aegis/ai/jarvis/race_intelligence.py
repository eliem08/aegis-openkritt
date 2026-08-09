"""Bounded synchronized race execution and idempotency/state reasoning."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from threading import Barrier
from typing import Callable

from aegis.ai.agentic_os import AuthorizationEnvelope


class RaceOutcome(str, Enum):
    DOUBLE_EXECUTION = "double_execution"
    INVARIANT_VIOLATION = "invariant_violation"
    IDEMPOTENCY_FAILURE = "idempotency_failure"
    RETRY_DUPLICATED_EFFECT = "retry_duplicated_effect"
    CONSISTENT = "consistent"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class AttemptResult:
    attempt_id: str
    status_code: int | None
    effect_ids: tuple[str, ...] = ()
    state_digest: str = ""
    timed_out: bool = False
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RaceExperiment:
    experiment_id: str
    results: tuple[AttemptResult, ...]
    before_state_digest: str
    after_state_digest: str
    max_allowed_effects: int = 1
    shared_idempotency_key_digest: str = ""
    synthetic_resource: bool = False
    synchronized: bool = False


@dataclass(frozen=True, slots=True)
class RaceVerdict:
    verdict_id: str
    outcome: RaceOutcome
    reason: str
    confidence: float
    experiment: RaceExperiment
    evidence: tuple[str, ...]


class BoundedConcurrencyHarness:
    """Run a small synchronized callback set only under a verified state-change grant."""

    def __init__(self, *, grant_verifier, max_concurrency: int = 8) -> None:
        if max_concurrency < 2 or max_concurrency > 8:
            raise ValueError("max_concurrency must be between 2 and 8")
        self.grant_verifier = grant_verifier
        self.max_concurrency = max_concurrency

    def run(
        self, *, attempts: int, operation: Callable[[int], AttemptResult],
        authorization: AuthorizationEnvelope,
    ) -> tuple[AttemptResult, ...]:
        grant = authorization.grant
        if (
            attempts < 2 or attempts > self.max_concurrency
            or attempts > authorization.budget.max_requests
            or grant is None or grant.scope_digest != authorization.scope_digest
            or not grant.verify(self.grant_verifier) or not grant.network_allowed
            or not grant.state_change_allowed or not grant.human_approval
        ):
            raise PermissionError("bounded race execution requires a valid scoped state-change grant")
        barrier = Barrier(attempts)

        def invoke(index: int) -> AttemptResult:
            barrier.wait(timeout=5)
            return operation(index)

        with ThreadPoolExecutor(max_workers=attempts, thread_name_prefix="aegis-race") as pool:
            return tuple(pool.map(invoke, range(attempts)))


class RaceConditionAgent:
    def evaluate(self, experiment: RaceExperiment) -> RaceVerdict:
        verdict_id = "race-verdict:" + sha256(experiment.experiment_id.encode()).hexdigest()[:20]
        evidence = tuple(dict.fromkeys(
            item for result in experiment.results for item in result.evidence
        ))
        if not experiment.synthetic_resource or not experiment.synchronized:
            return RaceVerdict(verdict_id, RaceOutcome.INCONCLUSIVE,
                               "synthetic resource and synchronized attempts are required",
                               0.0, experiment, evidence)
        if not experiment.before_state_digest or not experiment.after_state_digest:
            return RaceVerdict(verdict_id, RaceOutcome.INCONCLUSIVE,
                               "before and after state readback are required", 0.0,
                               experiment, evidence)
        effect_ids = tuple(dict.fromkeys(
            effect for result in experiment.results for effect in result.effect_ids
        ))
        successes = sum(
            result.status_code is not None and 200 <= result.status_code < 300
            for result in experiment.results
        )
        if experiment.shared_idempotency_key_digest and len(effect_ids) > 1:
            return RaceVerdict(verdict_id, RaceOutcome.IDEMPOTENCY_FAILURE,
                               "one idempotency key produced multiple unique effects", 0.98,
                               experiment, evidence)
        timed_out = any(result.timed_out or result.status_code is None
                        or result.status_code >= 500 for result in experiment.results)
        if timed_out and len(effect_ids) > experiment.max_allowed_effects:
            return RaceVerdict(verdict_id, RaceOutcome.RETRY_DUPLICATED_EFFECT,
                               "retry after timeout or 5xx duplicated a persistent effect", 0.96,
                               experiment, evidence)
        if len(effect_ids) > experiment.max_allowed_effects:
            return RaceVerdict(verdict_id, RaceOutcome.DOUBLE_EXECUTION,
                               "concurrent attempts produced more effects than the invariant allows",
                               0.97, experiment, evidence)
        if successes > experiment.max_allowed_effects:
            return RaceVerdict(verdict_id, RaceOutcome.INVARIANT_VIOLATION,
                               "more concurrent operations succeeded than the invariant allows",
                               0.9, experiment, evidence)
        if len(experiment.results) < 2:
            return RaceVerdict(verdict_id, RaceOutcome.INCONCLUSIVE,
                               "at least two attempts are required", 0.0, experiment, evidence)
        return RaceVerdict(verdict_id, RaceOutcome.CONSISTENT,
                           "bounded concurrent attempts preserved the declared effect invariant",
                           0.85, experiment, evidence)


def retry_experiment(
    experiment_id: str, first: AttemptResult, retry: AttemptResult,
    *, before_state_digest: str, after_state_digest: str,
    synthetic_resource: bool = True,
) -> RaceExperiment:
    return RaceExperiment(experiment_id, (first, retry), before_state_digest,
                          after_state_digest, 1, "", synthetic_resource, True)


__all__ = [
    "AttemptResult", "BoundedConcurrencyHarness", "RaceConditionAgent", "RaceExperiment",
    "RaceOutcome", "RaceVerdict", "retry_experiment",
]
