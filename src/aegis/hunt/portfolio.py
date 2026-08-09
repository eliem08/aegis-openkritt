"""Explainable repository portfolio planning for the three-pass hunter."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from aegis.scheduler.profit import HuntOpportunity, ProfitScore, allocate, score

from .repository_runtime import repository_opportunities


@dataclass(frozen=True)
class PortfolioDecision:
    opportunity_id: str
    handle: str
    repo_full: str
    selected: bool
    reason: str
    score: ProfitScore
    opportunity: HuntOpportunity

    def summary(self) -> dict:
        return {
            "opportunity_id": self.opportunity_id,
            "handle": self.handle,
            "repo": self.repo_full,
            "selected": self.selected,
            "reason": self.reason,
            "gross_expected_value_usd": str(self.score.gross_expected_value),
            "estimated_cost_usd": str(self.score.total_cost),
            "net_expected_value_usd": str(self.score.net_expected_value),
            "missing_bounty": self.score.missing_bounty,
            "asset_kind": self.opportunity.asset_kind,
            "scope_digest": self.opportunity.scope_digest,
            "authorization_id": self.opportunity.authorization_id,
            "prerequisite_state": self.opportunity.prerequisite_state,
            "p_find": self.opportunity.p_find,
            "p_valid": self.opportunity.p_valid,
            "p_unique": self.opportunity.p_unique,
            "p_accepted": self.opportunity.p_accepted,
        }


def plan_portfolio(
    programs,
    *,
    capacity: int,
    expected_bounties: dict[str, Decimal] | None = None,
    p_valid: float = 0.5,
    p_accepted: float = 0.5,
    model_cost: Decimal = Decimal("0.02"),
    scanner_cost: Decimal = Decimal("0.05"),
    verification_time_cost: Decimal = Decimal("0.50"),
    exploration_fraction: float = 0.2,
    reward_policies: dict | None = None,
    authorizations: dict | None = None,
    p_find: float = 0.5,
) -> list[PortfolioDecision]:
    """Rank discovered repositories without fabricating missing payout amounts.

    ``reward_policies`` (handle -> RewardPolicy) scales each program's acceptance
    probability by its reward floor, so programs that only pay for easily-exploitable
    high/critical (e.g. Coinbase cb-mpc) are deprioritized versus programs that pay
    for the severities our scans realistically produce.
    """
    opportunities = list(repository_opportunities(
        programs,
        expected_bounties=expected_bounties,
        authorizations=authorizations,
        p_find=p_find,
        p_valid=p_valid,
        p_accepted=p_accepted,
        model_cost=model_cost,
        scanner_cost=scanner_cost,
        verification_cost=verification_time_cost,
        reward_policies=reward_policies,
    ))

    chosen = {
        item.opportunity_id: (result, reason)
        for item, result, reason in allocate(
            opportunities, capacity=capacity, exploration_fraction=exploration_fraction,
        )
    }
    decisions = []
    for opportunity in opportunities:
        handle, repo_full = opportunity.program_handle, opportunity.asset_locator
        if opportunity.opportunity_id in chosen:
            result, reason = chosen[opportunity.opportunity_id]
            if result.missing_bounty:
                reason = "exploration_missing_bounty"
            selected = True
        else:
            result = score(opportunity.features)
            reason = "portfolio_capacity"
            selected = False
        decisions.append(PortfolioDecision(
            opportunity_id=opportunity.opportunity_id,
            handle=handle,
            repo_full=repo_full,
            selected=selected,
            reason=reason,
            score=result,
            opportunity=opportunity,
        ))
    return sorted(decisions, key=lambda item: (not item.selected, item.opportunity_id))
