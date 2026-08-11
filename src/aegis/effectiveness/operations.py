"""Read-only operator queues and deterministic profitability summaries."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Mapping

from .economics import project_realized_economics
from .models import FactType, OutcomeState
from .repository import EffectivenessRepository
from .statistics import calculate_profitability_profiles

REPORT_QUALITY_FIELDS = (
    "title", "affected_asset", "repro_steps", "observed_result", "expected_result",
    "impact", "evidence", "negative_controls", "scope_proof",
)


def pending_review_queue(repository: EffectivenessRepository) -> tuple[dict[str, Any], ...]:
    """Return deterministic human-review work; this never submits or authorizes work."""
    facts = repository.facts()
    types_by_subject: dict[str, set[FactType]] = {}
    metadata_by_subject: dict[str, Mapping[str, Any]] = {}
    for fact in facts:
        types_by_subject.setdefault(fact.subject_id, set()).add(fact.fact_type)
        if fact.fact_type in {FactType.INDEPENDENTLY_VERIFIED, FactType.SKEPTIC_TRIAGE_SURVIVED}:
            metadata_by_subject[fact.subject_id] = fact.metadata or {}
    latest = {item.payload.subject_id: item for item in repository.latest_outcomes()}
    rows = []
    for subject in repository.subjects():
        types = types_by_subject.get(subject.subject_id, set())
        verified = bool(types & {FactType.INDEPENDENTLY_VERIFIED, FactType.SKEPTIC_TRIAGE_SURVIVED})
        approved = bool(types & {FactType.HUMAN_APPROVED, FactType.REPORT_HUMAN_APPROVED})
        outcome = latest.get(subject.subject_id)
        pending = outcome is not None and outcome.payload.state is OutcomeState.PENDING
        if not ((verified and not approved) or pending):
            continue
        metadata = metadata_by_subject.get(subject.subject_id, {})
        missing = tuple(name for name in REPORT_QUALITY_FIELDS if not metadata.get(name))
        rows.append({
            "subject_id": subject.subject_id, "program_id": subject.program_id,
            "asset_id": subject.asset_id, "technique": subject.technique,
            "reason": "PENDING_PROGRAM_OUTCOME" if pending else "HUMAN_REVIEW_REQUIRED",
            "report_quality": "READY" if not missing else "INCOMPLETE",
            "missing_report_fields": missing,
        })
    return tuple(sorted(rows, key=lambda row: (row["program_id"], row["technique"], row["subject_id"])))


def daily_profitability_document(
    repository: EffectivenessRepository, *, computed_at: str,
) -> dict[str, Any]:
    """Build a deterministic projection from immutable facts; projections are not facts."""
    profiles = calculate_profitability_profiles(repository, computed_at=computed_at)
    outcomes = repository.latest_outcomes()
    accepted_revenue = sum(
        (item.payload.bounty_usd for item in outcomes
         if item.payload.state is OutcomeState.ACCEPTED and item.payload.bounty_usd is not None),
        start=0,
    )
    all_costs = tuple(item.payload for item in repository.costs())
    economics = project_realized_economics(
        accepted_revenue if outcomes else None, all_costs, computed_at=computed_at,
    )
    return {
        "schema_version": 2, "authoritative": repository.authoritative,
        "computed_at": computed_at, "model_version": profiles.model_version,
        "profiles": asdict(profiles), "economics": asdict(economics),
        "review_queue": pending_review_queue(repository),
        "shadow_batches": repository.shadow_batches(),
        "campaigns": repository.campaigns(),
        "production_authority_changed": False,
        "human_submission_mandatory": True,
    }
