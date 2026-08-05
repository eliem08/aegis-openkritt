"""Expected-profit ranking: class-fit + realistic payout."""

from __future__ import annotations

from aegis.ai.auto_hunt import HuntTarget
from aegis.ai.profit import class_fit, expected_profit, rank_by_profit, realistic_payout


def test_contract_and_php_fit_higher_than_go():
    sol = HuntTarget(repository="x/pool", kind="contract", reward_ceiling=50000, findability=0.5)
    php = HuntTarget(repository="mainwp/mainwp", reward_ceiling=2500, findability=0.7)
    go = HuntTarget(repository="hyperledger/fabric-go", reward_ceiling=3000, findability=0.5)
    assert class_fit(sol) > class_fit(php) > class_fit(go)


def test_realistic_payout_is_fraction_of_ceiling():
    t = HuntTarget(repository="a/b", reward_ceiling=10000)
    assert realistic_payout(t, "critical") == 3500          # 0.35 of ceiling
    assert realistic_payout(t, "medium") == 2500


def test_class_fit_boosts_profit_over_base_ev():
    php = HuntTarget(repository="wordpress/some-plugin", reward_ceiling=2000, findability=0.6)
    from aegis.ai.auto_hunt import expected_value, AutoHuntConfig
    assert class_fit(php) == 1.20                                        # recognised as PHP
    assert expected_profit(php) > expected_value(php, AutoHuntConfig())   # fit 1.20 > 1.0


def test_ranking_orders_by_profit():
    a = HuntTarget(repository="x/sol", kind="contract", reward_ceiling=40000, findability=0.4)
    b = HuntTarget(repository="y/go-lib", reward_ceiling=2000, findability=0.5)
    ranked = rank_by_profit([b, a])
    assert ranked[0][0].repository == "x/sol"      # high-ceiling contract wins on profit
    assert ranked[0][1] > ranked[1][1]
