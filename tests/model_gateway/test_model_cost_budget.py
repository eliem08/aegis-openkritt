from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal

import pytest

from aegis.model_gateway.budget import AtomicModelBudget, ModelBudgetError


def test_concurrent_reservations_cannot_exceed_cycle_limit():
    budget = AtomicModelBudget(cycle_limit=Decimal("2"), daily_limit=Decimal("10"))

    def reserve(index):
        try:
            budget.reserve(
                f"r-{index}", tenant_id="t", cycle_id="c", day="2026-08-03",
                maximum=Decimal("0.3"),
            )
            return True
        except ModelBudgetError:
            return False

    with ThreadPoolExecutor(max_workers=20) as pool:
        accepted = list(pool.map(reserve, range(20)))
    assert sum(accepted) == 6
    assert budget.spent("t", cycle_id="c") == Decimal("1.8")


def test_finalize_releases_unused_amount_and_is_idempotent():
    budget = AtomicModelBudget()
    budget.reserve(
        "r", tenant_id="t", cycle_id="c", day="2026-08-03", maximum=Decimal("0.5"),
    )
    first = budget.finalize("r", Decimal("0.1"))
    second = budget.finalize("r", Decimal("0.1"))
    assert first == second
    assert budget.spent("t", cycle_id="c") == Decimal("0.1")
    with pytest.raises(ModelBudgetError, match="finalize_conflict"):
        budget.finalize("r", Decimal("0.2"))


def test_reservation_id_conflict_fails_closed():
    budget = AtomicModelBudget()
    budget.reserve(
        "r", tenant_id="t", cycle_id="c", day="2026-08-03", maximum=Decimal("0.1"),
    )
    with pytest.raises(ModelBudgetError, match="reservation_conflict"):
        budget.reserve(
            "r", tenant_id="other", cycle_id="c", day="2026-08-03",
            maximum=Decimal("0.1"),
        )
