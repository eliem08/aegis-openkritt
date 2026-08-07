from aegis.ai.auto_hunt import AutoHuntConfig, AutoHunter, HuntOutcome, HuntTarget
from aegis.ai.profit import estimate_profit, rank_by_net_profit


def test_net_profit_subtracts_cost_and_duplicate_risk():
    target = HuntTarget(
        repository="x/expensive",
        reward_ceiling=10_000,
        findability=0.8,
        likely_payout=2_000,
        estimated_compute_cost_usd=40,
        human_review_minutes=60,
        duplicate_risk=0.5,
    )
    estimate = estimate_profit(target, AutoHuntConfig(human_hourly_cost_usd=20))
    assert estimate.projected_cost_usd == 60
    assert estimate.duplicate_adjusted_ev < estimate.gross_ev
    assert estimate.net_ev == round(estimate.duplicate_adjusted_ev - 60, 2)


def test_net_ranking_rejects_high_headline_low_margin_target():
    noisy = HuntTarget(
        repository="x/noisy",
        reward_ceiling=100_000,
        findability=0.5,
        estimated_compute_cost_usd=5_000,
        duplicate_risk=0.95,
    )
    focused = HuntTarget(
        repository="wordpress/focused-plugin",
        reward_ceiling=5_000,
        findability=0.8,
        likely_payout=1_500,
        estimated_compute_cost_usd=10,
        duplicate_risk=0.05,
    )
    ranked = rank_by_net_profit([noisy, focused], AutoHuntConfig())
    assert ranked[0][0].repository == focused.repository
    assert ranked[0][1].net_ev > 0 > ranked[1][1].net_ev


def test_hunter_stops_before_projected_budget_overrun():
    hunted = []

    def hunt_fn(target, samples):
        hunted.append(target.repository)
        return HuntOutcome(target=target, candidates=1)

    targets = [
        HuntTarget(
            repository="a",
            reward_ceiling=5_000,
            findability=0.9,
            likely_payout=2_000,
            estimated_compute_cost_usd=6,
        ),
        HuntTarget(
            repository="b",
            reward_ceiling=4_000,
            findability=0.8,
            likely_payout=1_500,
            estimated_compute_cost_usd=6,
        ),
    ]
    session = AutoHunter(
        hunt_fn,
        config=AutoHuntConfig(max_targets=2, max_projected_spend_usd=10),
    ).run(targets)
    assert hunted == ["a"]
    assert session.status == "budget_exhausted"
    assert session.projected_spend_usd == 6
    assert session.candidate_total == 1
    assert session.confirmed_total == 0
