"""Canonical cross-asset opportunity economics and portfolio allocation."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Mapping


def _probability(name: str, value: float) -> float:
    value = float(value)
    if not 0 <= value <= 1:
        raise ValueError(f"{name} must be in [0, 1]")
    return value


def _money(name: str, value: Decimal | float | int) -> Decimal:
    result = Decimal(str(value))
    if result < 0:
        raise ValueError(f"{name} cannot be negative")
    return result


@dataclass(frozen=True)
class ProfitFeatures:
    """Economic inputs shared by opportunities and compatibility adapters."""

    p_valid: float
    p_accepted: float
    expected_bounty: Decimal | None
    uniqueness: float
    model_cost: Decimal = Decimal(0)
    scanner_cost: Decimal = Decimal(0)
    verification_time_cost: Decimal = Decimal(0)
    uncertainty: float = 0.5
    p_find: float = 1.0
    p_reproducible: float = 1.0
    compute_cost: Decimal = Decimal(0)
    validation_cost: Decimal = Decimal(0)
    human_review_cost: Decimal = Decimal(0)

    def __post_init__(self) -> None:
        for name in (
            "p_find", "p_valid", "p_accepted", "uniqueness",
            "p_reproducible", "uncertainty",
        ):
            _probability(name, getattr(self, name))
        for name in (
            "model_cost", "scanner_cost", "verification_time_cost",
            "compute_cost", "validation_cost", "human_review_cost",
        ):
            _money(name, getattr(self, name))
        if self.expected_bounty is not None:
            _money("expected_bounty", self.expected_bounty)


@dataclass(frozen=True)
class ProfitScore:
    gross_expected_value: Decimal
    total_cost: Decimal
    net_expected_value: Decimal
    missing_bounty: bool


@dataclass(frozen=True, init=False)
class HuntOpportunity:
    """One authorized, explainable research opportunity across any asset kind.

    The custom constructor accepts the historical ``(id, ProfitFeatures)`` shape and
    the former ``aegis.ai.portfolio_agents.Opportunity`` keyword shape. This keeps
    callers compatible while making this object the sole production opportunity
    contract.
    """

    opportunity_id: str
    program_id: str = ""
    program_handle: str = ""
    asset_id: str = ""
    asset_kind: str = "unresolved"
    asset_locator: str = ""
    scope_digest: str = ""
    authorization_id: str = ""
    attack_surface: str = ""
    weakness_family: str = ""
    prerequisite_state: str = "ready"
    freshness_score: float = 0.5
    change_score: float = 0.0
    coverage_score: float = 0.0
    estimated_payout_usd: Decimal | None = None
    p_find: float = 1.0
    p_valid: float = 0.5
    p_unique: float = 0.5
    p_accepted: float = 0.5
    p_reproducible: float = 1.0
    compute_cost_usd: Decimal = Decimal(0)
    model_cost_usd: Decimal = Decimal(0)
    scanner_cost_usd: Decimal = Decimal(0)
    validation_cost_usd: Decimal = Decimal(0)
    human_cost_usd: Decimal = Decimal(0)
    opportunity_cost_usd: Decimal = Decimal(0)
    expected_human_minutes: float = 0.0
    information_gain: float = 0.0
    uncertainty: float = 0.5
    provenance: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __init__(
        self,
        opportunity_id: str,
        features: ProfitFeatures | str | None = None,
        *legacy_values: Any,
        **values: Any,
    ) -> None:
        if not str(opportunity_id).strip():
            raise ValueError("opportunity_id is required")
        if features is not None and not isinstance(features, ProfitFeatures):
            positional = (features, *legacy_values)
            legacy_names = (
                "program_id", "weakness_family", "estimated_payout_usd", "p_valid",
                "p_accepted", "p_unique", "p_reproducible",
            )
            if len(positional) > len(legacy_names):
                raise TypeError("too many positional arguments for HuntOpportunity")
            values = {**dict(zip(legacy_names, positional)), **values}
            features = None
        elif legacy_values:
            raise TypeError("ProfitFeatures form accepts no additional positional arguments")
        aliases = {
            "bug_class": "weakness_family",
            "surface": "attack_surface",
            "payout": "estimated_payout_usd",
            "expected_payout_usd": "estimated_payout_usd",
            "api_cost_usd": "model_cost_usd",
            "review_minutes": "expected_human_minutes",
        }
        values = {aliases.get(key, key): value for key, value in values.items()}
        if features is not None:
            values = {
                "estimated_payout_usd": features.expected_bounty,
                "p_find": features.p_find,
                "p_valid": features.p_valid,
                "p_unique": features.uniqueness,
                "p_accepted": features.p_accepted,
                "p_reproducible": features.p_reproducible,
                "compute_cost_usd": features.compute_cost,
                "model_cost_usd": features.model_cost,
                "scanner_cost_usd": features.scanner_cost,
                "validation_cost_usd": features.validation_cost,
                "human_cost_usd": features.human_review_cost,
                "opportunity_cost_usd": features.verification_time_cost,
                "uncertainty": features.uncertainty,
                **values,
            }
        known = {item.name for item in self.__dataclass_fields__.values()}
        unknown = set(values) - known
        if unknown:
            raise TypeError(f"unexpected HuntOpportunity fields: {sorted(unknown)}")
        object.__setattr__(self, "opportunity_id", str(opportunity_id))
        for name, item in self.__dataclass_fields__.items():
            if name == "opportunity_id":
                continue
            if name in values:
                value = values[name]
            elif item.default_factory is not None and item.default_factory is not field:
                try:
                    value = item.default_factory()
                except TypeError:
                    value = item.default
            else:
                value = item.default
            object.__setattr__(self, name, value)
        self._validate()

    def _validate(self) -> None:
        for name in (
            "p_find", "p_valid", "p_unique", "p_accepted", "p_reproducible",
            "freshness_score", "change_score", "coverage_score", "information_gain",
            "uncertainty",
        ):
            _probability(name, getattr(self, name))
        for name in (
            "compute_cost_usd", "model_cost_usd", "scanner_cost_usd",
            "validation_cost_usd", "human_cost_usd", "opportunity_cost_usd",
        ):
            object.__setattr__(self, name, _money(name, getattr(self, name)))
        if self.estimated_payout_usd is not None:
            object.__setattr__(
                self, "estimated_payout_usd",
                _money("estimated_payout_usd", self.estimated_payout_usd),
            )
        if self.expected_human_minutes < 0:
            raise ValueError("expected_human_minutes cannot be negative")

    @property
    def features(self) -> ProfitFeatures:
        return ProfitFeatures(
            p_find=self.p_find,
            p_valid=self.p_valid,
            p_accepted=self.p_accepted,
            expected_bounty=self.estimated_payout_usd,
            uniqueness=self.p_unique,
            p_reproducible=self.p_reproducible,
            compute_cost=self.compute_cost_usd,
            model_cost=self.model_cost_usd,
            scanner_cost=self.scanner_cost_usd,
            validation_cost=self.validation_cost_usd,
            human_review_cost=self.human_cost_usd,
            verification_time_cost=self.opportunity_cost_usd,
            uncertainty=self.uncertainty,
        )

    @property
    def bug_class(self) -> str:
        return self.weakness_family

    @property
    def expected_payout_usd(self) -> float | None:
        return None if self.estimated_payout_usd is None else float(self.estimated_payout_usd)

    @property
    def api_cost_usd(self) -> float:
        return float(self.model_cost_usd)

    @property
    def review_minutes(self) -> float:
        return self.expected_human_minutes

    def success_probability(self) -> float:
        return math.prod((self.p_find, self.p_valid, self.p_unique,
                          self.p_accepted, self.p_reproducible))

    def gross_value(self) -> float:
        return float(score(self.features).gross_expected_value)

    def total_cost(self, human_hour_cost_usd: float = 0.0) -> float:
        review = (self.expected_human_minutes / 60.0) * max(0.0, human_hour_cost_usd)
        return float(score(self.features).total_cost) + review

    def expected_value(self, human_hour_cost_usd: float = 0.0) -> float:
        return self.gross_value() - self.total_cost(human_hour_cost_usd)

    def roi_per_review_hour(self, human_hour_cost_usd: float = 0.0) -> float:
        hours = max(self.expected_human_minutes / 60.0, 1.0 / 60.0)
        return self.expected_value(human_hour_cost_usd) / hours


# Backward-compatible name. New code should import HuntOpportunity.
Opportunity = HuntOpportunity


def score(features: ProfitFeatures) -> ProfitScore:
    bounty = features.expected_bounty or Decimal(0)
    gross = bounty
    for probability in (
        features.p_find,
        features.p_valid,
        features.uniqueness,
        features.p_accepted,
        features.p_reproducible,
    ):
        gross *= Decimal(str(probability))
    costs = (
        features.compute_cost
        + features.model_cost
        + features.scanner_cost
        + features.validation_cost
        + features.human_review_cost
        + features.verification_time_cost
    )
    return ProfitScore(gross, costs, gross - costs, features.expected_bounty is None)


def rank(opportunities: list[HuntOpportunity]) -> list[tuple[HuntOpportunity, ProfitScore]]:
    ranked = [(item, score(item.features)) for item in opportunities]
    return sorted(
        ranked,
        key=lambda pair: (
            pair[1].missing_bounty,
            -pair[1].net_expected_value,
            -pair[0].information_gain,
            -pair[0].uncertainty,
            pair[0].opportunity_id,
        ),
    )


def allocate(
    opportunities: list[HuntOpportunity],
    *,
    capacity: int,
    exploration_fraction: float = 0.2,
) -> list[tuple[HuntOpportunity, ProfitScore, str]]:
    """Choose positive-EV work and reserve bounded uncertainty exploration."""
    if capacity <= 0:
        return []
    _probability("exploration_fraction", exploration_fraction)
    ordered = rank(opportunities)
    explore_count = min(len(ordered), round(capacity * exploration_fraction))
    exploit_count = max(0, capacity - explore_count)
    exploit_pool = [pair for pair in ordered if pair[1].net_expected_value > 0]
    exploit = exploit_pool[:exploit_count]
    used = {item.opportunity_id for item, _ in exploit}
    remainder = [pair for pair in ordered if pair[0].opportunity_id not in used]
    exploration = sorted(
        remainder,
        key=lambda pair: (
            -pair[0].uncertainty,
            -pair[0].information_gain,
            pair[0].opportunity_id,
        ),
    )[:explore_count]
    selected = [(item, result, "expected_value") for item, result in exploit]
    selected.extend((item, result, "exploration") for item, result in exploration)
    return selected[:capacity]
