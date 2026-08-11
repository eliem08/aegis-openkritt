"""Deterministic realized-cost projections over immutable observations."""

from __future__ import annotations

from decimal import Decimal
from typing import Iterable

from .models import (
    CostObservation,
    EconomicProjection,
    EconomicsState,
    money,
    utc_now,
)

MODEL_VERSION = "realized-economics-v2.0"
MACHINE_FIELDS = (
    "model_api_cost_usd",
    "scanner_compute_cost_usd",
    "cloud_cost_usd",
    "oast_cost_usd",
    "browser_device_cost_usd",
)
HUMAN_MINUTE_FIELDS = (
    "human_review_minutes",
    "human_submission_minutes",
    "human_other_minutes",
)


def project_realized_economics(
    realized_revenue_usd: Decimal | str | int | float | None,
    observations: Iterable[CostObservation],
    *,
    computed_at: str | None = None,
) -> EconomicProjection:
    """Project factual profit without interpreting missing monetary inputs as zero."""
    revenue = money(realized_revenue_usd, field_name="realized_revenue_usd")
    items = tuple(observations)
    missing: set[str] = set()
    if revenue is None:
        missing.add("realized_revenue_usd")
    if not items:
        missing.update((*MACHINE_FIELDS, *HUMAN_MINUTE_FIELDS, "human_hourly_rate_usd"))

    machine_cost = Decimal(0)
    human_cost = Decimal(0)
    human_minutes = Decimal(0)
    for item in items:
        for name in MACHINE_FIELDS:
            value = getattr(item, name)
            if value is None:
                missing.add(name)
            else:
                machine_cost += value
        for name in HUMAN_MINUTE_FIELDS:
            value = getattr(item, name)
            if value is None:
                missing.add(name)
            else:
                human_minutes += value
        if item.human_hourly_rate_usd is None:
            missing.add("human_hourly_rate_usd")
        if item.human_cost_usd is not None:
            human_cost += item.human_cost_usd

    machine_complete = not any(name in missing for name in MACHINE_FIELDS)
    human_complete = not any(
        name in missing for name in (*HUMAN_MINUTE_FIELDS, "human_hourly_rate_usd")
    )
    excluding_human = (
        revenue - machine_cost if revenue is not None and machine_complete else None
    )
    realized_profit = (
        excluding_human - human_cost
        if excluding_human is not None and human_complete
        else None
    )
    return EconomicProjection(
        state=(EconomicsState.COMPLETE if not missing else EconomicsState.INCOMPLETE),
        realized_revenue_usd=revenue,
        machine_infrastructure_cost_usd=(machine_cost if machine_complete else None),
        human_cost_usd=(human_cost if human_complete else None),
        total_human_minutes=(human_minutes if not any(
            name in missing for name in HUMAN_MINUTE_FIELDS
        ) else None),
        realized_profit_excluding_human_cost_usd=excluding_human,
        realized_profit_usd=realized_profit,
        missing_inputs=tuple(sorted(missing)),
        sample_count=len(items),
        model_version=MODEL_VERSION,
        computed_at=computed_at or utc_now(),
    )
