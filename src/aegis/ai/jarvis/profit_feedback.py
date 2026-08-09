"""Apply durable bounty-outcome learning to live opportunity economics."""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
from typing import Iterable

from ..portfolio_agents import Opportunity
from .state_store import JarvisStateStore, LearnedPrior


def prior_weight(samples: int) -> float:
    """Increase trust in personal history gradually while preserving exploration."""
    if samples <= 0:
        return 0.0
    return min(0.85, samples / (samples + 5.0))


def calibrate_opportunity(opportunity: Opportunity, prior: LearnedPrior) -> Opportunity:
    """Blend platform/program priors into an opportunity without erasing base estimates."""
    weight = prior_weight(prior.samples)
    if weight == 0.0:
        return opportunity
    payout = opportunity.expected_payout_usd
    if prior.mean_payout_usd is not None and prior.mean_payout_usd > 0:
        payout = (
            prior.mean_payout_usd if payout is None
            else (1.0 - weight) * payout + weight * prior.mean_payout_usd
        )
    accepted = (1.0 - weight) * opportunity.p_accepted + weight * prior.acceptance_probability
    unique = (1.0 - weight) * opportunity.p_unique + weight * prior.uniqueness_probability
    return replace(
        opportunity,
        estimated_payout_usd=None if payout is None else Decimal(str(max(0.0, payout))),
        p_accepted=max(0.0, min(1.0, accepted)),
        p_unique=max(0.0, min(1.0, unique)),
    )


def calibrate_opportunities(
    store: JarvisStateStore,
    opportunities: Iterable[Opportunity],
) -> tuple[Opportunity, ...]:
    calibrated = []
    for opportunity in opportunities:
        prior = store.learned_prior(opportunity.program_id, opportunity.bug_class)
        calibrated.append(calibrate_opportunity(opportunity, prior))
    return tuple(calibrated)


def rank_calibrated_opportunities(
    store: JarvisStateStore,
    opportunities: Iterable[Opportunity],
    *,
    human_hour_cost_usd: float = 0.0,
) -> tuple[Opportunity, ...]:
    calibrated = calibrate_opportunities(store, opportunities)
    return tuple(
        sorted(
            calibrated,
            key=lambda opportunity: (
                opportunity.expected_value(human_hour_cost_usd),
                opportunity.information_gain,
                opportunity.opportunity_id,
            ),
            reverse=True,
        )
    )
