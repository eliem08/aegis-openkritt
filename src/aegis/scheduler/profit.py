"""Explainable expected-net-value ranking for bounded hunting work."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal


def _probability(name: str, value: float) -> float:
    if not 0 <= value <= 1:
        raise ValueError(f"{name} must be in [0, 1]")
    return value


@dataclass(frozen=True)
class ProfitFeatures:
    p_valid: float
    p_accepted: float
    expected_bounty: Decimal | None
    uniqueness: float
    model_cost: Decimal = Decimal(0)
    scanner_cost: Decimal = Decimal(0)
    verification_time_cost: Decimal = Decimal(0)
    uncertainty: float = 0.5

    def __post_init__(self) -> None:
        for name in ("p_valid", "p_accepted", "uniqueness", "uncertainty"):
            _probability(name, getattr(self, name))
        for name in ("model_cost", "scanner_cost", "verification_time_cost"):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} cannot be negative")
        if self.expected_bounty is not None and self.expected_bounty < 0:
            raise ValueError("expected_bounty cannot be negative")


@dataclass(frozen=True)
class ProfitScore:
    gross_expected_value: Decimal
    total_cost: Decimal
    net_expected_value: Decimal
    missing_bounty: bool


@dataclass(frozen=True)
class Opportunity:
    opportunity_id: str
    features: ProfitFeatures


def score(features: ProfitFeatures) -> ProfitScore:
    bounty = features.expected_bounty or Decimal(0)
    gross = (
        Decimal(str(features.p_valid))
        * Decimal(str(features.p_accepted))
        * bounty
        * Decimal(str(features.uniqueness))
    )
    costs = features.model_cost + features.scanner_cost + features.verification_time_cost
    return ProfitScore(gross, costs, gross - costs, features.expected_bounty is None)


def rank(opportunities: list[Opportunity]) -> list[tuple[Opportunity, ProfitScore]]:
    ranked = [(item, score(item.features)) for item in opportunities]
    return sorted(
        ranked,
        key=lambda pair: (
            pair[1].missing_bounty,
            -pair[1].net_expected_value,
            -pair[0].features.uncertainty,
            pair[0].opportunity_id,
        ),
    )


def allocate(
    opportunities: list[Opportunity],
    *,
    capacity: int,
    exploration_fraction: float = 0.2,
) -> list[tuple[Opportunity, ProfitScore, str]]:
    """Choose profitable work while reserving deterministic uncertainty exploration."""
    if capacity <= 0:
        return []
    _probability("exploration_fraction", exploration_fraction)
    ordered = rank(opportunities)
    explore_count = min(len(ordered), round(capacity * exploration_fraction))
    exploit_count = max(0, min(len(ordered), capacity - explore_count))
    exploit = ordered[:exploit_count]
    used = {item.opportunity_id for item, _ in exploit}
    remainder = [pair for pair in ordered if pair[0].opportunity_id not in used]
    exploration = sorted(
        remainder,
        key=lambda pair: (-pair[0].features.uncertainty, pair[0].opportunity_id),
    )[:explore_count]
    selected = [(item, result, "expected_value") for item, result in exploit]
    selected.extend((item, result, "exploration") for item, result in exploration)
    return selected[:capacity]
