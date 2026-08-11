"""Deterministic funnel, economic, timing, and uncertainty metrics."""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from decimal import Decimal
from statistics import median
from typing import Callable, Iterable

from .models import ConfidenceState, FactType, OutcomeRecord, OutcomeState, confidence_for
from .repository import EffectivenessRepository


@dataclass(frozen=True, slots=True)
class MetricRow:
    key: str
    opportunities: int
    reproduced: int
    skeptic_survived: int
    human_approved: int
    submitted: int
    accepted: int
    duplicates: int
    informative: int
    not_applicable: int
    rejected: int
    externally_resolved: int
    acceptance_rate: float | None
    acceptance_interval: tuple[float, float] | None
    duplicate_rate: float | None
    duplicate_interval: tuple[float, float] | None
    known_bounty_usd: Decimal
    unknown_bounty_outcomes: int
    median_known_payout_usd: Decimal | None
    model_api_cost_usd: Decimal
    compute_cost_usd: Decimal
    total_recorded_cost_usd: Decimal
    human_review_minutes: Decimal
    realized_profit_usd: Decimal | None
    known_realized_profit_usd: Decimal
    profit_per_review_hour_usd: Decimal | None
    mean_time_to_triage_seconds: float | None
    realized_ev_usd: Decimal | None
    confidence: ConfidenceState

    @property
    def samples(self) -> int:
        return self.externally_resolved


@dataclass(frozen=True, slots=True)
class EffectivenessMetrics:
    overall: MetricRow
    by_technique: tuple[MetricRow, ...]
    by_weakness_family: tuple[MetricRow, ...]
    by_program: tuple[MetricRow, ...]
    by_asset_class: tuple[MetricRow, ...]
    by_authentication_mode: tuple[MetricRow, ...]
    by_execution_mode: tuple[MetricRow, ...]


def _wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float] | None:
    if total == 0:
        return None
    probability = successes / total
    denominator = 1 + z * z / total
    center = (probability + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(
        probability * (1 - probability) / total + z * z / (4 * total * total)
    ) / denominator
    return max(0.0, center - margin), min(1.0, center + margin)


def _metric_row(key: str, subjects, fact_types, outcomes: list[OutcomeRecord]) -> MetricRow:
    states = [item.payload.state for item in outcomes]
    accepted = states.count(OutcomeState.ACCEPTED)
    duplicates = states.count(OutcomeState.DUPLICATE)
    informative = states.count(OutcomeState.INFORMATIVE)
    not_applicable = states.count(OutcomeState.NOT_APPLICABLE)
    rejected = states.count(OutcomeState.REJECTED)
    external = accepted + duplicates + informative + not_applicable
    known_bounties = [item.payload.bounty_usd for item in outcomes
                      if item.payload.bounty_usd is not None]
    unknown_bounties = sum(item.payload.bounty_usd is None for item in outcomes)
    model_cost = sum((item.payload.model_api_cost_usd for item in outcomes), Decimal(0))
    compute_cost = sum((item.payload.compute_cost_usd for item in outcomes), Decimal(0))
    review_minutes = sum((item.payload.human_review_minutes for item in outcomes), Decimal(0))
    known_bounty = sum(known_bounties, Decimal(0))
    total_cost = model_cost + compute_cost
    complete_money = unknown_bounties == 0
    realized_profit = known_bounty - total_cost if complete_money else None
    known_profit = known_bounty - total_cost
    profit_hour = None
    if complete_money and review_minutes > 0:
        profit_hour = realized_profit * Decimal(60) / review_minutes
    triage_seconds = []
    for item in outcomes:
        if item.payload.submitted_at and item.payload.triaged_at:
            from .models import parse_timestamp

            submitted = parse_timestamp(item.payload.submitted_at, field_name="submitted_at")
            triaged = parse_timestamp(item.payload.triaged_at, field_name="triaged_at")
            triage_seconds.append((triaged - submitted).total_seconds())
    facts_by_type = {fact_type: set() for fact_type in FactType}
    for subject_id, fact_type in fact_types:
        facts_by_type[fact_type].add(subject_id)
    acceptance_rate = accepted / external if external else None
    duplicate_rate = duplicates / external if external else None
    return MetricRow(
        key=key, opportunities=len(subjects),
        reproduced=len(facts_by_type[FactType.FINDING_REPRODUCED]),
        skeptic_survived=len(facts_by_type[FactType.SKEPTIC_TRIAGE_SURVIVED]),
        human_approved=len(facts_by_type[FactType.REPORT_HUMAN_APPROVED]),
        submitted=len(facts_by_type[FactType.REPORT_SUBMITTED]),
        accepted=accepted, duplicates=duplicates, informative=informative,
        not_applicable=not_applicable, rejected=rejected, externally_resolved=external,
        acceptance_rate=acceptance_rate, acceptance_interval=_wilson(accepted, external),
        duplicate_rate=duplicate_rate, duplicate_interval=_wilson(duplicates, external),
        known_bounty_usd=known_bounty, unknown_bounty_outcomes=unknown_bounties,
        median_known_payout_usd=(Decimal(str(median(known_bounties))) if known_bounties else None),
        model_api_cost_usd=model_cost, compute_cost_usd=compute_cost,
        total_recorded_cost_usd=total_cost, human_review_minutes=review_minutes,
        realized_profit_usd=realized_profit, known_realized_profit_usd=known_profit,
        profit_per_review_hour_usd=profit_hour,
        mean_time_to_triage_seconds=(sum(triage_seconds) / len(triage_seconds)
                                     if triage_seconds else None),
        realized_ev_usd=(realized_profit / external
                         if realized_profit is not None and external else None),
        confidence=confidence_for(external),
    )


def _group(
    subjects, facts, outcomes_by_subject, key_fn: Callable,
) -> tuple[MetricRow, ...]:
    grouped = defaultdict(list)
    for subject in subjects:
        grouped[key_fn(subject)].append(subject)
    output = []
    for key, items in grouped.items():
        subject_ids = {item.subject_id for item in items}
        fact_types = [(fact.subject_id, fact.fact_type) for fact in facts
                      if fact.subject_id in subject_ids]
        outcomes = [outcomes_by_subject[item] for item in subject_ids
                    if item in outcomes_by_subject]
        output.append(_metric_row(str(key), items, fact_types, outcomes))
    return tuple(sorted(output, key=lambda row: row.key))


def calculate_metrics(repository: EffectivenessRepository) -> EffectivenessMetrics:
    subjects = repository.subjects()
    facts = repository.facts()
    outcomes_by_subject = {item.payload.subject_id: item for item in repository.latest_outcomes()}
    all_fact_types = [(fact.subject_id, fact.fact_type) for fact in facts]
    overall = _metric_row("overall", subjects, all_fact_types, list(outcomes_by_subject.values()))
    return EffectivenessMetrics(
        overall=overall,
        by_technique=_group(subjects, facts, outcomes_by_subject, lambda item: item.technique),
        by_weakness_family=_group(
            subjects, facts, outcomes_by_subject, lambda item: item.weakness_family,
        ),
        by_program=_group(subjects, facts, outcomes_by_subject, lambda item: item.program_id),
        by_asset_class=_group(subjects, facts, outcomes_by_subject, lambda item: item.asset_class),
        by_authentication_mode=_group(
            subjects, facts, outcomes_by_subject, lambda item: item.authentication_mode,
        ),
        by_execution_mode=_group(
            subjects, facts, outcomes_by_subject, lambda item: item.execution_mode,
        ),
    )


def rows_for(metrics: EffectivenessMetrics) -> Iterable[tuple[str, tuple[MetricRow, ...]]]:
    yield "technique", metrics.by_technique
    yield "weakness_family", metrics.by_weakness_family
    yield "program", metrics.by_program
    yield "asset_class", metrics.by_asset_class
    yield "authentication_mode", metrics.by_authentication_mode
    yield "execution_mode", metrics.by_execution_mode
