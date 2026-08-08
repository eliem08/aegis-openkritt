from __future__ import annotations

from aegis.ai.auto_hunt import AutoHuntConfig, HuntTarget
from aegis.ai.portfolio_agents import Opportunity
from aegis.ai.profit import estimate_profit, target_opportunity


def test_opportunity_components_are_consistent():
    opportunity = Opportunity(
        opportunity_id="x",
        program_id="p",
        bug_class="c",
        expected_payout_usd=1000,
        p_valid=0.5,
        p_accepted=0.5,
        p_unique=0.5,
        p_reproducible=0.5,
        compute_cost_usd=10,
        review_minutes=30,
    )
    assert opportunity.success_probability() == 0.0625
    assert opportunity.gross_value() == 62.5
    assert opportunity.total_cost(20) == 20
    assert opportunity.expected_value(20) == 42.5


def test_target_profit_estimate_is_adapter_over_common_opportunity():
    config = AutoHuntConfig(human_hourly_cost_usd=20)
    target = HuntTarget(
        repository="wordpress/example",
        handle="example",
        reward_ceiling=5000,
        findability=0.8,
        duplicate_risk=0.2,
        estimated_compute_cost_usd=10,
        human_review_minutes=30,
    )
    opportunity = target_opportunity(target, config)
    estimate = estimate_profit(target, config)
    assert estimate.net_ev == round(opportunity.expected_value(20), 2)
    assert estimate.projected_cost_usd == round(opportunity.total_cost(20), 2)
