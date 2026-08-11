"""Immutable domain records for measured hunting effectiveness."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import Enum
from hashlib import sha256
from typing import Any, Mapping


class OutcomeState(str, Enum):
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    INFORMATIVE = "informative"
    NOT_APPLICABLE = "not_applicable"
    REJECTED = "rejected"


class FactType(str, Enum):
    OPPORTUNITY_GENERATED = "opportunity_generated"
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
    if hasattr(value, "__dataclass_fields__"):
        value = asdict(value)
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

    def __post_init__(self) -> None:
        if not all((self.fact_id, self.subject_id, self.idempotency_key)):
            raise ValueError("fact identity is required")
        parse_timestamp(self.observed_at, field_name="observed_at")
        if len(self.source_digest) != 64:
            raise ValueError("fact source_digest must be a SHA-256 digest")


@dataclass(frozen=True, slots=True)
class OutcomeInput:
    subject_id: str
    state: OutcomeState
    submitted_severity: str | None
    triaged_severity: str | None
    bounty_usd: Decimal | None
    submitted_at: str | None
    triaged_at: str | None
    resolved_at: str
    human_review_minutes: Decimal
    model_api_cost_usd: Decimal
    compute_cost_usd: Decimal
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
        if self.state is not OutcomeState.REJECTED and submitted is None:
            raise ValueError("externally resolved outcomes require submitted_at")
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
