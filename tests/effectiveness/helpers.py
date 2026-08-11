from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from aegis.effectiveness.models import (
    CostObservation,
    EffectivenessFact,
    EffectivenessSubject,
    FactType,
    OutcomeInput,
    OutcomeState,
)

DIGEST = "a" * 64


def subject(index=1, *, technique="authorization-boundary"):
    return EffectivenessSubject(
        subject_id=f"subject-{index}", run_id=f"run-{index}", mission_id=f"mission-{index}",
        opportunity_id=f"opportunity-{index}", technique=technique, program_id="program",
        asset_id=f"asset-{index}", weakness_family="authorization", asset_class="web_api",
        authentication_mode="authenticated", execution_mode="dynamic",
        evidence_digest=DIGEST, source_digest="b" * 64,
        created_at=datetime.now(UTC).isoformat(),
    )


def fact(item, fact_type=FactType.OPPORTUNITY_GENERATED):
    return EffectivenessFact(
        fact_id=f"fact-{item.subject_id}-{fact_type.value}", subject_id=item.subject_id,
        fact_type=fact_type, observed_at=datetime.now(UTC).isoformat(), source_digest="c" * 64,
        idempotency_key=f"{item.subject_id}:{fact_type.value}",
    )


def outcome(
    item, *, state=OutcomeState.ACCEPTED, bounty=Decimal("100"), key=None,
    supersedes=None,
):
    submitted = datetime.now(UTC) - timedelta(hours=2)
    triaged = submitted + timedelta(hours=1)
    return OutcomeInput(
        subject_id=item.subject_id, state=state, submitted_severity="high",
        triaged_severity="medium", bounty_usd=bounty, submitted_at=submitted.isoformat(),
        triaged_at=triaged.isoformat(), resolved_at=(triaged + timedelta(minutes=30)).isoformat(),
        human_review_minutes=Decimal("30"), model_api_cost_usd=Decimal("2.50"),
        compute_cost_usd=Decimal("1.25"), analyst_note="human reviewed", operator_id="operator",
        source_digest="d" * 64, idempotency_key=key or f"outcome:{item.subject_id}",
        supersedes_outcome_event_id=supersedes,
    )


def cost(item, *, key="cost:1", rate=Decimal("120"), model=Decimal("2.50")):
    return CostObservation(
        cost_observation_id=f"cost-{key}",
        subject_id=item.subject_id,
        campaign_id=None,
        model_api_cost_usd=model,
        scanner_compute_cost_usd=Decimal("1.25"),
        cloud_cost_usd=Decimal("0"),
        oast_cost_usd=Decimal("0"),
        browser_device_cost_usd=Decimal("0"),
        human_review_minutes=Decimal("30"),
        human_submission_minutes=Decimal("15"),
        human_other_minutes=Decimal("0"),
        human_hourly_rate_usd=rate,
        observed_at="2026-08-11T06:00:00+00:00",
        operator_id="operator",
        source_digest=DIGEST,
        idempotency_key=key,
    )
