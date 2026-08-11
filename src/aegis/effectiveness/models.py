"""Immutable domain records for measured hunting effectiveness."""

from __future__ import annotations

import json
from dataclasses import dataclass, fields, is_dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import Enum
from hashlib import sha256
from types import MappingProxyType
from typing import Any, Mapping


class OutcomeState(str, Enum):
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    INFORMATIVE = "informative"
    NOT_APPLICABLE = "not_applicable"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"
    PENDING = "pending"


class FactType(str, Enum):
    OPPORTUNITY_GENERATED = "opportunity_generated"
    CANDIDATE_GENERATED = "candidate_generated"
    RUNTIME_OBSERVED = "runtime_observed"
    LOCALLY_REPRODUCED = "locally_reproduced"
    INDEPENDENTLY_VERIFIED = "independently_verified"
    HUMAN_APPROVED = "human_approved"
    SUBMITTED = "submitted"
    TRIAGED = "triaged"
    ACCEPTED = "accepted"
    PAID = "paid"
    # V1 stored values remain valid and are never rewritten.
    FINDING_REPRODUCED = "finding_reproduced"
    SKEPTIC_TRIAGE_SURVIVED = "skeptic_triage_survived"
    REPORT_HUMAN_APPROVED = "report_human_approved"
    REPORT_SUBMITTED = "report_submitted"


class ConfidenceState(str, Enum):
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    MODERATE_CONFIDENCE = "MODERATE_CONFIDENCE"
    CALIBRATION_ELIGIBLE = "CALIBRATION_ELIGIBLE"


class StorageState(str, Enum):
    READY = "READY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"


class EconomicsState(str, Enum):
    COMPLETE = "ECONOMICS_COMPLETE"
    INCOMPLETE = "ECONOMICS_INCOMPLETE"


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def parse_timestamp(value: str | None, *, field_name: str) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must include a timezone")
    return parsed.astimezone(UTC)


def money(value: Decimal | str | int | float | None, *, field_name: str) -> Decimal | None:
    if value is None:
        return None
    result = Decimal(str(value))
    if not result.is_finite() or result < 0:
        raise ValueError(f"{field_name} must be a finite non-negative amount")
    return result


def canonical_document(value: Any) -> Any:
    if is_dataclass(value):
        return {item.name: canonical_document(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): canonical_document(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [canonical_document(item) for item in value]
    return value


def payload_digest(value: Any) -> str:
    document = canonical_document(value)
    raw = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256(raw.encode("utf-8")).hexdigest()


def confidence_for(samples: int) -> ConfidenceState:
    if samples < 0:
        raise ValueError("samples cannot be negative")
    if samples < 5:
        return ConfidenceState.INSUFFICIENT_DATA
    if samples < 15:
        return ConfidenceState.LOW_CONFIDENCE
    if samples < 30:
        return ConfidenceState.MODERATE_CONFIDENCE
    return ConfidenceState.CALIBRATION_ELIGIBLE


@dataclass(frozen=True, slots=True)
class EffectivenessSubject:
    subject_id: str
    run_id: str
    mission_id: str
    opportunity_id: str
    technique: str
    program_id: str
    asset_id: str
    weakness_family: str
    asset_class: str
    authentication_mode: str
    execution_mode: str
    evidence_digest: str
    source_digest: str
    created_at: str
    candidate_finding_id: str | None = None
    human_decision_id: str | None = None
    submission_id: str | None = None

    def __post_init__(self) -> None:
        identity = (
            self.subject_id, self.run_id, self.mission_id, self.opportunity_id,
            self.technique, self.program_id, self.asset_id, self.weakness_family,
            self.asset_class, self.authentication_mode, self.execution_mode,
        )
        if any(not str(item).strip() for item in identity):
            raise ValueError("effectiveness subject lineage and dimensions are required")
        for name, digest in (("evidence_digest", self.evidence_digest),
                             ("source_digest", self.source_digest)):
            if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest.lower()):
                raise ValueError(f"{name} must be a SHA-256 digest")
        parse_timestamp(self.created_at, field_name="created_at")


@dataclass(frozen=True, slots=True)
class EffectivenessFact:
    fact_id: str
    subject_id: str
    fact_type: FactType
    observed_at: str
    source_digest: str
    idempotency_key: str
    metadata: Mapping[str, Any] | None = None
    model_version: str | None = None

    def __post_init__(self) -> None:
        if not all((self.fact_id, self.subject_id, self.idempotency_key)):
            raise ValueError("fact identity is required")
        parse_timestamp(self.observed_at, field_name="observed_at")
        if len(self.source_digest) != 64:
            raise ValueError("fact source_digest must be a SHA-256 digest")
        metadata = canonical_document(dict(self.metadata or {}))
        object.__setattr__(self, "metadata", MappingProxyType(metadata))
        if self.model_version is not None and not self.model_version.strip():
            raise ValueError("fact model_version cannot be blank")


@dataclass(frozen=True, slots=True)
class OutcomeInput:
    subject_id: str
    state: OutcomeState
    submitted_severity: str | None
    triaged_severity: str | None
    bounty_usd: Decimal | None
    submitted_at: str | None
    triaged_at: str | None
    resolved_at: str | None
    human_review_minutes: Decimal | None
    model_api_cost_usd: Decimal | None
    compute_cost_usd: Decimal | None
    analyst_note: str | None
    operator_id: str
    source_digest: str
    idempotency_key: str
    supersedes_outcome_event_id: str | None = None

    def __post_init__(self) -> None:
        if not all((self.subject_id, self.operator_id, self.source_digest, self.idempotency_key)):
            raise ValueError("outcome identity, operator, provenance, and idempotency are required")
        if len(self.source_digest) != 64:
            raise ValueError("outcome source_digest must be a SHA-256 digest")
        object.__setattr__(self, "bounty_usd", money(self.bounty_usd, field_name="bounty_usd"))
        for field_name in ("human_review_minutes", "model_api_cost_usd", "compute_cost_usd"):
            object.__setattr__(self, field_name, money(getattr(self, field_name), field_name=field_name))
        submitted = parse_timestamp(self.submitted_at, field_name="submitted_at")
        triaged = parse_timestamp(self.triaged_at, field_name="triaged_at")
        resolved = parse_timestamp(self.resolved_at, field_name="resolved_at")
        if self.state not in {OutcomeState.REJECTED} and submitted is None:
            raise ValueError("externally resolved outcomes require submitted_at")
        if self.state is not OutcomeState.PENDING and resolved is None:
            raise ValueError("terminal outcomes require resolved_at")
        if submitted and triaged and triaged < submitted:
            raise ValueError("triaged_at cannot precede submitted_at")
        if submitted and resolved and resolved < submitted:
            raise ValueError("resolved_at cannot precede submitted_at")
        if triaged and resolved and resolved < triaged:
            raise ValueError("resolved_at cannot precede triaged_at")
        if self.analyst_note is not None and len(self.analyst_note) > 4000:
            raise ValueError("analyst_note exceeds 4000 characters")


@dataclass(frozen=True, slots=True)
class OutcomeRecord:
    outcome_event_id: str
    version: int
    recorded_at: str
    payload: OutcomeInput


@dataclass(frozen=True, slots=True)
class CostObservation:
    cost_observation_id: str
    subject_id: str
    campaign_id: str | None
    model_api_cost_usd: Decimal | None
    scanner_compute_cost_usd: Decimal | None
    cloud_cost_usd: Decimal | None
    oast_cost_usd: Decimal | None
    browser_device_cost_usd: Decimal | None
    human_review_minutes: Decimal | None
    human_submission_minutes: Decimal | None
    human_other_minutes: Decimal | None
    human_hourly_rate_usd: Decimal | None
    observed_at: str
    operator_id: str
    source_digest: str
    idempotency_key: str
    calculation_version: str = "human-cost-v1"

    def __post_init__(self) -> None:
        identity = (
            self.cost_observation_id, self.subject_id, self.operator_id,
            self.source_digest, self.idempotency_key, self.calculation_version,
        )
        if any(not str(item).strip() for item in identity):
            raise ValueError("cost identity, lineage, provenance, and version are required")
        if len(self.source_digest) != 64:
            raise ValueError("cost source_digest must be a SHA-256 digest")
        parse_timestamp(self.observed_at, field_name="observed_at")
        for name in (
            "model_api_cost_usd", "scanner_compute_cost_usd", "cloud_cost_usd",
            "oast_cost_usd", "browser_device_cost_usd", "human_review_minutes",
            "human_submission_minutes", "human_other_minutes", "human_hourly_rate_usd",
        ):
            object.__setattr__(self, name, money(getattr(self, name), field_name=name))

    @property
    def total_human_minutes(self) -> Decimal | None:
        values = (
            self.human_review_minutes, self.human_submission_minutes,
            self.human_other_minutes,
        )
        if any(value is None for value in values):
            return None
        return sum(values, Decimal(0))

    @property
    def human_cost_usd(self) -> Decimal | None:
        minutes = self.total_human_minutes
        if minutes is None or self.human_hourly_rate_usd is None:
            return None
        return minutes / Decimal(60) * self.human_hourly_rate_usd


@dataclass(frozen=True, slots=True)
class CostRecord:
    cost_record_id: str
    recorded_at: str
    payload: CostObservation


@dataclass(frozen=True, slots=True)
class EconomicProjection:
    state: EconomicsState
    realized_revenue_usd: Decimal | None
    machine_infrastructure_cost_usd: Decimal | None
    human_cost_usd: Decimal | None
    total_human_minutes: Decimal | None
    realized_profit_excluding_human_cost_usd: Decimal | None
    realized_profit_usd: Decimal | None
    missing_inputs: tuple[str, ...]
    sample_count: int
    model_version: str
    computed_at: str


@dataclass(frozen=True, slots=True)
class ShadowEntry:
    opportunity_id: str
    existing_rank: int
    existing_score: Decimal
    learned_rank: int
    learned_score: Decimal
    confidence: ConfidenceState
    samples: int
    fallback_reason: str | None

    def __post_init__(self) -> None:
        if not self.opportunity_id or min(self.existing_rank, self.learned_rank) < 1:
            raise ValueError("shadow entry identity and ranks are invalid")
        if self.samples < 0:
            raise ValueError("shadow samples cannot be negative")


@dataclass(frozen=True, slots=True)
class ShadowBatch:
    batch_id: str
    created_at: str
    input_digest: str
    idempotency_key: str
    entries: tuple[ShadowEntry, ...]

    def __post_init__(self) -> None:
        if not all((self.batch_id, self.input_digest, self.idempotency_key)) or not self.entries:
            raise ValueError("shadow batch identity and entries are required")
        if len(self.input_digest) != 64:
            raise ValueError("shadow input_digest must be a SHA-256 digest")
        parse_timestamp(self.created_at, field_name="created_at")
        ids = [entry.opportunity_id for entry in self.entries]
        if len(ids) != len(set(ids)):
            raise ValueError("shadow opportunity ids must be unique")
