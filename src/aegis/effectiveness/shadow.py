"""Outcome-informed ranking comparison with zero production authority."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from .metrics import MetricRow, calculate_metrics
from .models import ConfidenceState, ShadowBatch, ShadowEntry, payload_digest, utc_now
from .repository import EffectivenessRepository


@dataclass(frozen=True, slots=True)
class ShadowCandidate:
    opportunity_id: str
    technique: str
    existing_score: Decimal


def build_shadow_batch(
    repository: EffectivenessRepository,
    candidates: tuple[ShadowCandidate, ...],
    *,
    batch_id: str,
    idempotency_key: str,
) -> ShadowBatch:
    if not candidates:
        raise ValueError("shadow ranking requires at least one opportunity")
    existing = sorted(candidates, key=lambda item: (-item.existing_score, item.opportunity_id))
    existing_rank = {item.opportunity_id: index for index, item in enumerate(existing, 1)}
    metrics = {row.key: row for row in calculate_metrics(repository).by_technique}
    learned_scores: dict[str, Decimal] = {}
    metadata: dict[str, tuple[ConfidenceState, int, str | None]] = {}
    for candidate in candidates:
        row: MetricRow | None = metrics.get(candidate.technique)
        if row is None or row.confidence is not ConfidenceState.CALIBRATION_ELIGIBLE:
            learned_scores[candidate.opportunity_id] = candidate.existing_score
            confidence = row.confidence if row else ConfidenceState.INSUFFICIENT_DATA
            samples = row.samples if row else 0
            metadata[candidate.opportunity_id] = (
                confidence, samples, "existing_priors_until_30_real_outcomes",
            )
            continue
        payout = row.median_known_payout_usd
        if payout is None or row.acceptance_rate is None or row.duplicate_rate is None:
            learned_scores[candidate.opportunity_id] = candidate.existing_score
            metadata[candidate.opportunity_id] = (
                row.confidence, row.samples, "insufficient_known_economics",
            )
            continue
        mean_cost = row.total_recorded_cost_usd / max(1, row.samples)
        learned_scores[candidate.opportunity_id] = (
            Decimal(str(row.acceptance_rate))
            * (Decimal(1) - Decimal(str(row.duplicate_rate))) * payout - mean_cost
        )
        metadata[candidate.opportunity_id] = (row.confidence, row.samples, None)
    learned = sorted(
        candidates, key=lambda item: (-learned_scores[item.opportunity_id], item.opportunity_id),
    )
    learned_rank = {item.opportunity_id: index for index, item in enumerate(learned, 1)}
    entries = tuple(ShadowEntry(
        opportunity_id=item.opportunity_id,
        existing_rank=existing_rank[item.opportunity_id], existing_score=item.existing_score,
        learned_rank=learned_rank[item.opportunity_id],
        learned_score=learned_scores[item.opportunity_id],
        confidence=metadata[item.opportunity_id][0], samples=metadata[item.opportunity_id][1],
        fallback_reason=metadata[item.opportunity_id][2],
    ) for item in existing)
    input_digest = payload_digest([
        {"opportunity_id": item.opportunity_id, "technique": item.technique,
         "existing_score": item.existing_score} for item in candidates
    ])
    return ShadowBatch(batch_id, utc_now(), input_digest, idempotency_key, entries)
