from decimal import Decimal

from aegis.scheduler.profit import (
    HuntOpportunity,
    Opportunity,
    ProfitFeatures,
    allocate,
    rank,
    score,
)


def _features(**changes):
    values = dict(
        p_valid=0.5,
        p_accepted=0.5,
        expected_bounty=Decimal("1000"),
        uniqueness=0.8,
        model_cost=Decimal("0.10"),
        scanner_cost=Decimal("0.05"),
        verification_time_cost=Decimal("10"),
        uncertainty=0.2,
    )
    values.update(changes)
    return ProfitFeatures(**values)


def test_score_exposes_gross_cost_and_net_components():
    result = score(_features())
    assert result.gross_expected_value == Decimal("200.000")
    assert result.total_cost == Decimal("10.15")
    assert result.net_expected_value == Decimal("189.850")
    assert result.missing_bounty is False


def test_probability_and_bounty_increase_rank_while_cost_and_duplicates_reduce_it():
    strong = Opportunity("strong", _features(p_valid=0.8, uniqueness=0.9))
    duplicate = Opportunity("duplicate", _features(p_valid=0.8, uniqueness=0.1))
    expensive = Opportunity("expensive", _features(model_cost=Decimal("500")))
    assert [item.opportunity_id for item, _ in rank([expensive, duplicate, strong])] == [
        "strong", "duplicate", "expensive",
    ]


def test_missing_bounty_is_explicit_and_does_not_outrank_known_positive_value():
    missing = Opportunity("missing", _features(expected_bounty=None, uncertainty=1))
    known = Opportunity("known", _features(expected_bounty=Decimal("10")))
    ordered = rank([missing, known])
    assert ordered[0][0].opportunity_id == "known"
    assert ordered[1][1].missing_bounty is True


def test_allocation_reserves_capacity_for_deterministic_exploration():
    items = [
        Opportunity(f"known-{index}", _features(expected_bounty=Decimal(1000 - index), uncertainty=0.1))
        for index in range(8)
    ]
    items.append(Opportunity("new-class", _features(expected_bounty=None, uncertainty=1.0)))
    selected = allocate(items, capacity=5, exploration_fraction=0.2)
    assert len(selected) == 5
    assert selected[-1][0].opportunity_id == "new-class"
    assert selected[-1][2] == "exploration"


def test_canonical_opportunity_exposes_cross_asset_identity_and_decomposed_economics():
    item = HuntOpportunity(
        opportunity_id="opp:api:authz",
        program_id="program:acme",
        program_handle="acme",
        asset_id="asset:api",
        asset_kind="api",
        asset_locator="https://api.acme.test",
        scope_digest="scope123",
        authorization_id="auth123",
        attack_surface="object-ownership",
        weakness_family="authz",
        estimated_payout_usd=Decimal("3000"),
        p_find=0.15,
        p_valid=0.74,
        p_unique=0.62,
        p_accepted=0.71,
        compute_cost_usd=Decimal("2"),
        model_cost_usd=Decimal("1"),
        scanner_cost_usd=Decimal("0.40"),
        validation_cost_usd=Decimal("4"),
        human_cost_usd=Decimal("5"),
        provenance=("synthetic-program",),
    )
    result = score(item.features)
    assert result.gross_expected_value == Decimal("146.586600000")
    assert result.total_cost == Decimal("12.40")
    assert result.net_expected_value == Decimal("134.186600000")
    assert item.asset_kind == "api" and item.scope_digest == "scope123"


def test_negative_value_is_not_exploited_but_can_use_bounded_exploration():
    negative = HuntOpportunity("negative", _features(expected_bounty=Decimal("1"),
                                                      model_cost=Decimal("50")),
                               uncertainty=1.0)
    positive = HuntOpportunity("positive", _features(expected_bounty=Decimal("1000")))
    exploited = allocate([negative, positive], capacity=1, exploration_fraction=0)
    assert [row[0].opportunity_id for row in exploited] == ["positive"]
    explored = allocate([negative], capacity=1, exploration_fraction=1)
    assert explored[0][0].opportunity_id == "negative"
    assert explored[0][2] == "exploration"
