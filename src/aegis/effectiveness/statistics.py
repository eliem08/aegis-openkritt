"""Versioned uncertainty-aware profitability projections over real ledger data."""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from decimal import Decimal
from statistics import pstdev
from typing import Callable

from .models import ConfidenceState, FactType, OutcomeRecord, OutcomeState, confidence_for, utc_now
from .repository import EffectivenessRepository

STATISTICAL_MODEL_VERSION = "effectiveness-bayesian-v2.0"
MIN_PAYOUT_SAMPLES = 5


@dataclass(frozen=True, slots=True)
class ProbabilityEstimate:
    mean: float
    lower: float
    upper: float
    sample_count: int
    confidence_class: ConfidenceState
    model_version: str
    computed_at: str


@dataclass(frozen=True, slots=True)
class PayoutEstimate:
    expected_payout_usd: Decimal | None
    payout_uncertainty_usd: Decimal | None
    status: str
    sample_count: int
    confidence_class: ConfidenceState
    model_version: str
    computed_at: str


@dataclass(frozen=True, slots=True)
class ProfitabilityProfile:
    key: str
    opportunities: int
    candidates: int
    reproduced: int
    independently_verified: int
    human_approved: int
    submitted: int
    accepted: int
    duplicates: int
    informative: int
    not_applicable: int
    rejected: int
    withdrawn: int
    pending: int
    p_valid: ProbabilityEstimate
    p_unique: ProbabilityEstimate
    p_accepted: ProbabilityEstimate
    payout: PayoutEstimate
    sample_count: int
    confidence_class: ConfidenceState
    model_version: str
    computed_at: str


@dataclass(frozen=True, slots=True)
class ProfitabilityProfiles:
    overall: ProfitabilityProfile
    by_program: tuple[ProfitabilityProfile, ...]
    by_technique: tuple[ProfitabilityProfile, ...]
    by_asset_class: tuple[ProfitabilityProfile, ...]
    by_weakness_family: tuple[ProfitabilityProfile, ...]
    by_severity: tuple[ProfitabilityProfile, ...]
    program_asset_technique_weakness: tuple[ProfitabilityProfile, ...]
    model_version: str
    computed_at: str


def beta_estimate(
    successes: int,
    trials: int,
    *,
    computed_at: str,
    alpha_prior: float = 1.0,
    beta_prior: float = 1.0,
) -> ProbabilityEstimate:
    if successes < 0 or trials < 0 or successes > trials:
        raise ValueError("probability counts are invalid")
    alpha = successes + alpha_prior
    beta = trials - successes + beta_prior
    center = alpha / (alpha + beta)
    variance = alpha * beta / ((alpha + beta) ** 2 * (alpha + beta + 1))
    margin = 1.96 * math.sqrt(variance)
    return ProbabilityEstimate(
        mean=center, lower=max(0.0, center - margin), upper=min(1.0, center + margin),
        sample_count=trials, confidence_class=confidence_for(trials),
        model_version=STATISTICAL_MODEL_VERSION, computed_at=computed_at,
    )


def _payout(outcomes: list[OutcomeRecord], computed_at: str) -> PayoutEstimate:
    values = [
        item.payload.bounty_usd for item in outcomes
        if item.payload.state is OutcomeState.ACCEPTED and item.payload.bounty_usd is not None
    ]
    samples = len(values)
    expected = None
    uncertainty = None
    status = "INSUFFICIENT_EVIDENCE"
    if samples >= MIN_PAYOUT_SAMPLES:
        expected = sum(values, Decimal(0)) / Decimal(samples)
        uncertainty = Decimal(str(pstdev(values))) if samples > 1 else Decimal(0)
        status = "ESTIMATED"
    return PayoutEstimate(
        expected_payout_usd=expected, payout_uncertainty_usd=uncertainty, status=status,
        sample_count=samples, confidence_class=confidence_for(samples),
        model_version=STATISTICAL_MODEL_VERSION, computed_at=computed_at,
    )


def _profile(key, subjects, facts, outcomes, computed_at) -> ProfitabilityProfile:
    subject_ids = {item.subject_id for item in subjects}
    fact_types = defaultdict(set)
    for item in facts:
        if item.subject_id in subject_ids:
            fact_types[item.fact_type].add(item.subject_id)
    scoped_outcomes = [item for item in outcomes if item.payload.subject_id in subject_ids]
    states = [item.payload.state for item in scoped_outcomes]
    candidates = len(fact_types[FactType.CANDIDATE_GENERATED])
    reproduced_ids = fact_types[FactType.LOCALLY_REPRODUCED] | fact_types[FactType.FINDING_REPRODUCED]
    verified_ids = (
        fact_types[FactType.INDEPENDENTLY_VERIFIED]
        | fact_types[FactType.SKEPTIC_TRIAGE_SURVIVED]
    )
    approved_ids = fact_types[FactType.HUMAN_APPROVED] | fact_types[FactType.REPORT_HUMAN_APPROVED]
    submitted_ids = fact_types[FactType.SUBMITTED] | fact_types[FactType.REPORT_SUBMITTED]
    accepted = states.count(OutcomeState.ACCEPTED)
    duplicates = states.count(OutcomeState.DUPLICATE)
    informative = states.count(OutcomeState.INFORMATIVE)
    not_applicable = states.count(OutcomeState.NOT_APPLICABLE)
    rejected = states.count(OutcomeState.REJECTED)
    withdrawn = states.count(OutcomeState.WITHDRAWN)
    pending = states.count(OutcomeState.PENDING)
    unique_trials = accepted + duplicates + informative + not_applicable
    unique_successes = accepted + informative + not_applicable
    accepted_trials = accepted + informative + not_applicable + rejected
    external_samples = unique_trials + rejected + withdrawn
    return ProfitabilityProfile(
        key=str(key), opportunities=len(subjects), candidates=candidates,
        reproduced=len(reproduced_ids), independently_verified=len(verified_ids),
        human_approved=len(approved_ids), submitted=len(submitted_ids), accepted=accepted,
        duplicates=duplicates, informative=informative, not_applicable=not_applicable,
        rejected=rejected, withdrawn=withdrawn, pending=pending,
        p_valid=beta_estimate(len(verified_ids), candidates, computed_at=computed_at),
        p_unique=beta_estimate(unique_successes, unique_trials, computed_at=computed_at),
        p_accepted=beta_estimate(accepted, accepted_trials, computed_at=computed_at),
        payout=_payout(scoped_outcomes, computed_at), sample_count=external_samples,
        confidence_class=confidence_for(external_samples),
        model_version=STATISTICAL_MODEL_VERSION, computed_at=computed_at,
    )


def _group(subjects, facts, outcomes, key_fn: Callable, computed_at):
    grouped = defaultdict(list)
    for item in subjects:
        grouped[str(key_fn(item))].append(item)
    return tuple(sorted(
        (_profile(key, items, facts, outcomes, computed_at) for key, items in grouped.items()),
        key=lambda row: row.key,
    ))


def calculate_profitability_profiles(
    repository: EffectivenessRepository,
    *,
    computed_at: str | None = None,
) -> ProfitabilityProfiles:
    timestamp = computed_at or utc_now()
    subjects = repository.subjects()
    facts = repository.facts()
    outcomes = repository.latest_outcomes()
    severity_by_subject = {
        item.payload.subject_id: (
            item.payload.triaged_severity or item.payload.submitted_severity or "unknown"
        ) for item in outcomes
    }
    return ProfitabilityProfiles(
        overall=_profile("overall", subjects, facts, outcomes, timestamp),
        by_program=_group(subjects, facts, outcomes, lambda item: item.program_id, timestamp),
        by_technique=_group(subjects, facts, outcomes, lambda item: item.technique, timestamp),
        by_asset_class=_group(subjects, facts, outcomes, lambda item: item.asset_class, timestamp),
        by_weakness_family=_group(
            subjects, facts, outcomes, lambda item: item.weakness_family, timestamp,
        ),
        by_severity=_group(
            subjects, facts, outcomes,
            lambda item: severity_by_subject.get(item.subject_id, "untriaged"), timestamp,
        ),
        program_asset_technique_weakness=_group(
            subjects, facts, outcomes,
            lambda item: "|".join((
                item.program_id, item.asset_class, item.technique, item.weakness_family,
            )), timestamp,
        ),
        model_version=STATISTICAL_MODEL_VERSION, computed_at=timestamp,
    )
