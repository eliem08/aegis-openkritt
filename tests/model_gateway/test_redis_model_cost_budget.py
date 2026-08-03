from decimal import Decimal

import pytest

from aegis.model_gateway.budget import ModelBudgetError
from aegis.model_gateway.redis_budget import RedisModelBudget, _dollars, _nanos


class FakeRedis:
    """Small semantic fake for the two Lua operations used by the budget."""

    def __init__(self):
        self.values = {}
        self.hashes = {}
        self.unavailable = False

    def eval(self, script, key_count, *items):
        if self.unavailable:
            raise OSError("redis unavailable")
        keys = items[:key_count]
        args = items[key_count:]
        if key_count == 3:
            cycle_key, day_key, reservation_key = keys
            amount, cycle_limit, daily_limit = map(int, args[:3])
            existing = self.hashes.get(reservation_key)
            if existing:
                if int(existing["reserved"]) != amount:
                    return -2
                if existing["state"] == "reserved":
                    return 2
                return -5
            if self.values.get(cycle_key, 0) + amount > cycle_limit:
                return -3
            if self.values.get(day_key, 0) + amount > daily_limit:
                return -4
            self.values[cycle_key] = self.values.get(cycle_key, 0) + amount
            self.values[day_key] = self.values.get(day_key, 0) + amount
            self.hashes[reservation_key] = {
                "reserved": str(amount), "actual": "", "state": "reserved",
                "tenant": args[5], "cycle": args[6], "day": args[7],
                "cycle_key": cycle_key, "day_key": day_key,
            }
            return 1
        reservation_key = keys[0]
        actual = int(args[0])
        reservation = self.hashes.get(reservation_key)
        if reservation is None:
            return -1
        if reservation["state"] == "finalized":
            return 2 if int(reservation["actual"]) == actual else -2
        reserved = int(reservation["reserved"])
        if actual > reserved:
            return -3
        release = reserved - actual
        self.values[reservation["cycle_key"]] -= release
        self.values[reservation["day_key"]] -= release
        reservation.update(actual=str(actual), state="finalized")
        return 1

    def get(self, key):
        if self.unavailable:
            raise OSError("redis unavailable")
        return self.values.get(key)

    def hgetall(self, key):
        return self.hashes.get(key, {})


def test_nanodollar_conversion_is_conservative_and_exact():
    assert _nanos(Decimal("0.0000000001")) == 1
    assert _dollars(1) == Decimal("0.000000001")
    with pytest.raises(ValueError):
        _nanos(Decimal("-0.01"))


def test_independent_instances_share_atomic_budget_and_finalize():
    redis = FakeRedis()
    first = RedisModelBudget(redis, cycle_limit=Decimal("1"), daily_limit=Decimal("2"))
    second = RedisModelBudget(redis, cycle_limit=Decimal("1"), daily_limit=Decimal("2"))
    first.reserve(
        "r-1", tenant_id="tenant", cycle_id="cycle", day="2026-08-03",
        maximum=Decimal("0.7"),
    )
    with pytest.raises(ModelBudgetError, match="cycle_budget_exhausted"):
        second.reserve(
            "r-2", tenant_id="tenant", cycle_id="cycle", day="2026-08-03",
            maximum=Decimal("0.4"),
        )
    finalized = second.finalize("r-1", Decimal("0.2"), tenant_id="tenant")
    assert finalized.actual == Decimal("0.2")
    assert first.spent("tenant", cycle_id="cycle") == Decimal("0.2")
    second.reserve(
        "r-2", tenant_id="tenant", cycle_id="cycle", day="2026-08-03",
        maximum=Decimal("0.4"),
    )


def test_reservation_and_finalization_are_idempotent_but_conflicts_fail():
    budget = RedisModelBudget(FakeRedis())
    kwargs = dict(tenant_id="tenant", cycle_id="cycle", day="2026-08-03")
    assert budget.reserve("r", maximum=Decimal("0.3"), **kwargs) == budget.reserve(
        "r", maximum=Decimal("0.3"), **kwargs,
    )
    assert budget.finalize("r", Decimal("0.1"), tenant_id="tenant") == budget.finalize(
        "r", Decimal("0.1"), tenant_id="tenant",
    )
    with pytest.raises(ModelBudgetError, match="finalize_conflict"):
        budget.finalize("r", Decimal("0.2"), tenant_id="tenant")
    with pytest.raises(ModelBudgetError, match="reservation_already_finalized"):
        budget.reserve("r", maximum=Decimal("0.3"), **kwargs)


def test_tenant_identity_and_redis_availability_fail_closed():
    redis = FakeRedis()
    budget = RedisModelBudget(redis)
    with pytest.raises(ModelBudgetError, match="tenant_identity_required"):
        budget.finalize("r", Decimal("0"))
    redis.unavailable = True
    with pytest.raises(ModelBudgetError, match="redis_budget_unavailable"):
        budget.reserve(
            "r", tenant_id="tenant", cycle_id="cycle", day="2026-08-03",
            maximum=Decimal("0.1"),
        )
