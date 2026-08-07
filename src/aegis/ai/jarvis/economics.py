"""Profit-aware portfolio allocation for autonomous research agents."""

from __future__ import annotations

import math
from dataclasses import dataclass

from .models import ResearchHypothesis


@dataclass(frozen=True)
class EconomicEstimate:
    expected_gross_usd: float
    expected_net_usd: float
    return_on_cost: float
    score: float


def estimate_hypothesis(
    hypothesis: ResearchHypothesis,
    *,
    validity_probability: float,
    acceptance_probability: float,
    reproducibility_probability: float,
    human_review_cost_usd: float = 0.0,
    exploration_bonus: float = 0.0,
) -> EconomicEstimate:
    probabilities = (
        validity_probability,
        acceptance_probability,
        reproducibility_probability,
        1.0 - hypothesis.duplicate_probability,
    )
    if any(probability < 0 or probability > 1 for probability in probabilities):
        raise ValueError("probabilities must be in [0, 1]")

    expected_gross = hypothesis.estimated_payout_usd
    for probability in probabilities:
        expected_gross *= probability

    cost = hypothesis.estimated_validation_cost_usd + human_review_cost_usd
    expected_net = expected_gross - cost
    return_on_cost = expected_net / max(cost, 0.01)
    score = expected_net + (
        exploration_bonus * max(0.0, min(1.0, hypothesis.novelty_score))
    )
    return EconomicEstimate(
        expected_gross_usd=expected_gross,
        expected_net_usd=expected_net,
        return_on_cost=return_on_cost,
        score=score,
    )


@dataclass
class ProgramArm:
    program_id: str
    wins: float = 1.0
    losses: float = 1.0
    samples: int = 0
    cumulative_net_usd: float = 0.0

    @property
    def posterior_mean(self) -> float:
        return self.wins / (self.wins + self.losses)

    def observe(self, *, positive: bool, net_usd: float) -> None:
        if positive:
            self.wins += 1.0
        else:
            self.losses += 1.0
        self.samples += 1
        self.cumulative_net_usd += net_usd


class PortfolioScheduler:
    """Deterministic UCB scheduler with payout feedback."""

    def __init__(self) -> None:
        self._arms: dict[str, ProgramArm] = {}

    def arm(self, program_id: str) -> ProgramArm:
        if program_id not in self._arms:
            self._arms[program_id] = ProgramArm(program_id=program_id)
        return self._arms[program_id]

    def observe(self, program_id: str, *, positive: bool, net_usd: float) -> None:
        self.arm(program_id).observe(positive=positive, net_usd=net_usd)

    def score(self, program_id: str) -> float:
        arm = self.arm(program_id)
        total_samples = sum(item.samples for item in self._arms.values())
        exploration = math.sqrt(
            2.0 * math.log(total_samples + 2.0) / (arm.samples + 1.0)
        )
        profit_signal = math.tanh(arm.cumulative_net_usd / 1000.0)
        return arm.posterior_mean + 0.25 * exploration + 0.25 * profit_signal

    def choose(self, program_ids: list[str]) -> str:
        if not program_ids:
            raise ValueError("at least one program is required")
        return max(program_ids, key=lambda program_id: (self.score(program_id), program_id))
