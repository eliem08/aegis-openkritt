"""Shadow-only economic ranking, allocation, and stop-loss recommendations."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from .economics import MACHINE_FIELDS
from .models import ConfidenceState, ShadowBatch, ShadowEntry, payload_digest, utc_now
from .repository import EffectivenessRepository
from .statistics import ProfitabilityProfile, calculate_profitability_profiles

SHADOW_POLICY_VERSION = "profitability-shadow-v2.0"


@dataclass(frozen=True, slots=True)
class EconomicShadowCandidate:
    opportunity_id: str
    program_id: str
    asset_class: str
    technique: str
    weakness_family: str
    existing_score: Decimal
    actual_selected: bool
    estimated_hours: Decimal | None
    estimated_requests: int | None
    estimated_compute_cost_usd: Decimal | None

    @property
    def matrix_key(self) -> str:
        return "|".join((
            self.program_id, self.asset_class, self.technique, self.weakness_family,
        ))


def _historical_cost(repository, candidate) -> Decimal | None:
    subject_ids = {
        item.subject_id for item in repository.subjects()
        if "|".join((item.program_id, item.asset_class, item.technique, item.weakness_family))
        == candidate.matrix_key
    }
    observations = [item.payload for item in repository.costs() if item.payload.subject_id in subject_ids]
    if not observations:
        return None
    totals = []
    for item in observations:
        machine = [getattr(item, name) for name in MACHINE_FIELDS]
        if any(value is None for value in machine) or item.human_cost_usd is None:
            return None
        totals.append(sum(machine, Decimal(0)) + item.human_cost_usd)
    return sum(totals, Decimal(0)) / Decimal(len(totals))


def _economic_values(
    profile: ProfitabilityProfile | None,
    cost: Decimal | None,
    candidate: EconomicShadowCandidate,
):
    if profile is None:
        return "ECONOMICS_INCOMPLETE", None, None, None, None, None, Decimal("0.5")
    duplicate = Decimal(str(1 - profile.p_unique.mean))
    payout = profile.payout.expected_payout_usd
    if payout is None or cost is None:
        return "ECONOMICS_INCOMPLETE", None, None, None, None, None, duplicate
    ev = (
        Decimal(str(profile.p_valid.mean))
        * Decimal(str(profile.p_unique.mean))
        * Decimal(str(profile.p_accepted.mean))
        * payout
        - cost
    )
    per_hour = ev / candidate.estimated_hours if candidate.estimated_hours else None
    per_request = ev / Decimal(candidate.estimated_requests) if candidate.estimated_requests else None
    per_compute = (
        ev / candidate.estimated_compute_cost_usd
        if candidate.estimated_compute_cost_usd else None
    )
    return "ECONOMICS_COMPLETE", ev, per_hour, per_request, per_compute, cost, duplicate


def _stop_loss(profile: ProfitabilityProfile | None, ev: Decimal | None) -> str:
    if profile is None or profile.sample_count < 5:
        return "CONTINUE"
    duplicate = Decimal(str(1 - profile.p_unique.mean))
    if profile.sample_count >= 15 and duplicate >= Decimal("0.75"):
        return "STOP"
    if profile.confidence_class in {
        ConfidenceState.MODERATE_CONFIDENCE, ConfidenceState.CALIBRATION_ELIGIBLE,
    } and ev is not None and ev < 0:
        return "STOP"
    if duplicate >= Decimal("0.5") or (ev is not None and ev < 0):
        return "DEPRIORITIZE"
    return "CONTINUE"


def build_shadow_policy_batch(
    repository: EffectivenessRepository,
    candidates: tuple[EconomicShadowCandidate, ...],
    *,
    batch_id: str,
    idempotency_key: str,
    selection_count: int,
    computed_at: str | None = None,
) -> ShadowBatch:
    if not candidates or selection_count < 1:
        raise ValueError("shadow policy requires candidates and a positive selection count")
    timestamp = computed_at or utc_now()
    selection_count = min(selection_count, len(candidates))
    profiles = {
        item.key: item for item in calculate_profitability_profiles(
            repository, computed_at=timestamp,
        ).program_asset_technique_weakness
    }
    existing = sorted(candidates, key=lambda item: (-item.existing_score, item.opportunity_id))
    existing_ranks = {item.opportunity_id: index for index, item in enumerate(existing, 1)}
    calculated = {}
    for item in candidates:
        profile = profiles.get(item.matrix_key)
        values = _economic_values(profile, _historical_cost(repository, item), item)
        status, ev, per_hour, per_request, per_compute, _cost, duplicate = values
        uncertainty = (
            (profile.p_valid.upper - profile.p_valid.lower)
            + (profile.p_unique.upper - profile.p_unique.lower)
            + (profile.p_accepted.upper - profile.p_accepted.lower)
            if profile else 3.0
        )
        calculated[item.opportunity_id] = {
            "profile": profile, "status": status, "ev": ev, "per_hour": per_hour,
            "per_request": per_request, "per_compute": per_compute,
            "duplicate": duplicate, "uncertainty": uncertainty,
            "score": ev if ev is not None else item.existing_score,
        }
    learned = sorted(
        candidates,
        key=lambda item: (-calculated[item.opportunity_id]["score"], item.opportunity_id),
    )
    learned_ranks = {item.opportunity_id: index for index, item in enumerate(learned, 1)}
    explore_slots = int(selection_count * 0.2)
    exploit_slots = selection_count - explore_slots
    exploit_ids = {item.opportunity_id for item in learned[:exploit_slots]}
    remaining = [item for item in candidates if item.opportunity_id not in exploit_ids]
    explore_ids = {
        item.opportunity_id for item in sorted(
            remaining,
            key=lambda item: (-calculated[item.opportunity_id]["uncertainty"], item.opportunity_id),
        )[:explore_slots]
    }
    selected_ids = exploit_ids | explore_ids
    entries = []
    for item in existing:
        values = calculated[item.opportunity_id]
        profile = values["profile"]
        mode = (
            "EXPLOIT" if item.opportunity_id in exploit_ids
            else "EXPLORE" if item.opportunity_id in explore_ids else "UNALLOCATED"
        )
        entries.append(ShadowEntry(
            opportunity_id=item.opportunity_id, existing_rank=existing_ranks[item.opportunity_id],
            existing_score=item.existing_score, learned_rank=learned_ranks[item.opportunity_id],
            learned_score=values["score"],
            confidence=(profile.confidence_class if profile else ConfidenceState.INSUFFICIENT_DATA),
            samples=(profile.sample_count if profile else 0),
            fallback_reason=(None if values["status"] == "ECONOMICS_COMPLETE"
                             else "incomplete_real_economics"),
            actual_selected=item.actual_selected,
            shadow_would_select=item.opportunity_id in selected_ids,
            economics_status=values["status"],
            stop_loss_recommendation=_stop_loss(profile, values["ev"]),
            allocation_mode=mode, p_duplicate=values["duplicate"], ev_usd=values["ev"],
            ev_per_hour_usd=values["per_hour"], ev_per_request_usd=values["per_request"],
            ev_per_compute_dollar=values["per_compute"],
            actual_realized_reward_usd=None, shadow_hypothetical_reward_usd=None,
            model_version=SHADOW_POLICY_VERSION, computed_at=timestamp,
        ))
    input_digest = payload_digest(candidates)
    return ShadowBatch(
        batch_id=batch_id, created_at=timestamp, input_digest=input_digest,
        idempotency_key=idempotency_key, entries=tuple(entries),
    )
