"""Profit-aware portfolio agents for allocating Aegis research effort."""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Iterable

from aegis.scheduler.profit import HuntOpportunity

from .agentic_os import AgentContext, AgentProposal, AgentRole, RiskClass

# Compatibility import for callers that historically sourced this name here.
Opportunity = HuntOpportunity


@dataclass
class ArmStats:
    successes: float = 1.0
    failures: float = 1.0
    payouts_usd: list[float] = field(default_factory=list)

    def observe(self, success: bool, payout_usd: float = 0.0) -> None:
        if success:
            self.successes += 1.0
            self.payouts_usd.append(max(0.0, payout_usd))
        else:
            self.failures += 1.0

    @property
    def mean_payout(self) -> float:
        if not self.payouts_usd:
            return 0.0
        return sum(self.payouts_usd) / len(self.payouts_usd)


class ThompsonPortfolio:
    """Deterministic-seed Thompson sampler for program/bug-class allocation."""

    def __init__(self, seed: int = 0) -> None:
        self._rng = random.Random(seed)
        self._arms: dict[str, ArmStats] = {}

    def arm(self, key: str) -> ArmStats:
        return self._arms.setdefault(key, ArmStats())

    def score(self, key: str) -> float:
        arm = self.arm(key)
        sampled_success = self._rng.betavariate(arm.successes, arm.failures)
        payout_scale = max(1.0, arm.mean_payout)
        return sampled_success * payout_scale

    def rank(self, keys: Iterable[str]) -> tuple[str, ...]:
        scored = [(self.score(key), key) for key in keys]
        scored.sort(key=lambda item: (-item[0], item[1]))
        return tuple(key for _, key in scored)


class ProfitabilityAgent:
    role = AgentRole.PROFITABILITY

    def __init__(self, human_hour_cost_usd: float = 0.0) -> None:
        self.human_hour_cost_usd = human_hour_cost_usd

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]:
        item = context.memory.get("portfolio:opportunities")
        if item is None or not isinstance(item.value, list):
            return ()
        opportunities = [op for op in item.value if isinstance(op, HuntOpportunity)]
        opportunities.sort(
            key=lambda op: (
                -op.expected_value(self.human_hour_cost_usd),
                -op.information_gain,
                op.opportunity_id,
            )
        )
        proposals: list[AgentProposal] = []
        for op in opportunities:
            net_ev = op.expected_value(self.human_hour_cost_usd)
            if net_ev <= 0:
                continue
            proposals.append(
                AgentProposal(
                    role=self.role,
                    action="allocate_research_budget",
                    rationale=(
                        f"Prioritize {op.program_id}/{op.bug_class}: positive duplicate-adjusted "
                        f"expected value of ${net_ev:.2f}."
                    ),
                    risk=RiskClass.OFFLINE,
                    expected_information_gain=max(0.0, min(1.0, op.information_gain)),
                    expected_cost_usd=float(op.compute_cost_usd + op.model_cost_usd),
                    expected_human_minutes=op.expected_human_minutes,
                    metadata={
                        "opportunity_id": op.opportunity_id,
                        "program_id": op.program_id,
                        "bug_class": op.bug_class,
                        "net_ev_usd": net_ev,
                        "roi_per_review_hour": op.roi_per_review_hour(self.human_hour_cost_usd),
                    },
                )
            )
        return tuple(proposals)


@dataclass(frozen=True)
class DuplicateFeatures:
    bug_class_prevalence: float
    code_age: float
    component_popularity: float
    public_disclosure_density: float
    recent_change_novelty: float
    prior_internal_duplicates: float


def estimate_duplicate_probability(features: DuplicateFeatures) -> float:
    """Transparent heuristic until enough outcomes exist for learned calibration."""
    duplicate_pressure = (
        0.22 * features.bug_class_prevalence
        + 0.18 * features.code_age
        + 0.18 * features.component_popularity
        + 0.2 * features.public_disclosure_density
        + 0.22 * features.prior_internal_duplicates
    )
    novelty_discount = 0.3 * features.recent_change_novelty
    return max(0.01, min(0.99, duplicate_pressure - novelty_discount))
