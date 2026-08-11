"""Repository contract and non-authoritative SQLite implementation."""

from __future__ import annotations

import json
import os
import sqlite3
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from typing import Iterable, Mapping, Protocol

from .models import (
    CampaignEvent,
    CampaignInput,
    CampaignRecord,
    ConfidenceState,
    CostObservation,
    CostRecord,
    EffectivenessFact,
    EffectivenessSubject,
    FactType,
    OutcomeInput,
    OutcomeRecord,
    OutcomeState,
    ShadowBatch,
    ShadowEntry,
    payload_digest,
    utc_now,
)


class EffectivenessError(RuntimeError):
    pass


class EffectivenessConflictError(EffectivenessError):
    pass


class EffectivenessStorageStateError(EffectivenessError):
    pass


class EffectivenessUnavailableError(EffectivenessError):
    pass


class EffectivenessRepository(Protocol):
    authoritative: bool

    def record_subject(
        self, subject: EffectivenessSubject, facts: Iterable[EffectivenessFact] = (),
    ) -> bool: ...
    def subject(self, subject_id: str) -> EffectivenessSubject | None: ...
    def subjects(self) -> tuple[EffectivenessSubject, ...]: ...
    def facts(self) -> tuple[EffectivenessFact, ...]: ...
    def record_fact(self, fact: EffectivenessFact) -> bool: ...
    def record_cost(self, cost: CostObservation) -> tuple[CostRecord, bool]: ...
    def costs(self, subject_id: str | None = None) -> tuple[CostRecord, ...]: ...
    def record_campaign(self, campaign: CampaignInput) -> tuple[CampaignRecord, bool]: ...
    def campaigns(self) -> tuple[CampaignRecord, ...]: ...
    def record_campaign_event(self, event: CampaignEvent) -> bool: ...
    def campaign_events(self, campaign_id: str) -> tuple[CampaignEvent, ...]: ...
    def record_outcome(self, outcome: OutcomeInput) -> tuple[OutcomeRecord, bool]: ...
    def outcome_history(self, subject_id: str) -> tuple[OutcomeRecord, ...]: ...
    def latest_outcomes(self) -> tuple[OutcomeRecord, ...]: ...
    def record_shadow_batch(self, batch: ShadowBatch) -> bool: ...
    def shadow_batches(self) -> tuple[ShadowBatch, ...]: ...
    def close(self) -> None: ...


SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS effectiveness_schema_migrations (
    version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL,
    applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS effectiveness_subjects (
    subject_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, mission_id TEXT NOT NULL,
    opportunity_id TEXT NOT NULL, technique TEXT NOT NULL, program_id TEXT NOT NULL,
    asset_id TEXT NOT NULL, weakness_family TEXT NOT NULL, asset_class TEXT NOT NULL,
    authentication_mode TEXT NOT NULL, execution_mode TEXT NOT NULL,
    evidence_digest TEXT NOT NULL, source_digest TEXT NOT NULL, created_at TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    UNIQUE(run_id, mission_id, opportunity_id, technique)
);
CREATE INDEX IF NOT EXISTS idx_effectiveness_subject_dimensions
    ON effectiveness_subjects(technique, weakness_family, program_id, asset_class);
CREATE INDEX IF NOT EXISTS idx_effectiveness_subject_modes
    ON effectiveness_subjects(authentication_mode, execution_mode);

CREATE TABLE IF NOT EXISTS effectiveness_facts (
    fact_id TEXT PRIMARY KEY,
    subject_id TEXT NOT NULL REFERENCES effectiveness_subjects(subject_id),
    fact_type TEXT NOT NULL, observed_at TEXT NOT NULL, source_digest TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE, payload_digest TEXT NOT NULL,
    UNIQUE(subject_id, fact_type, source_digest)
);
CREATE INDEX IF NOT EXISTS idx_effectiveness_facts_subject
    ON effectiveness_facts(subject_id, fact_type);

CREATE TABLE IF NOT EXISTS effectiveness_outcome_events (
    outcome_event_id TEXT PRIMARY KEY,
    subject_id TEXT NOT NULL REFERENCES effectiveness_subjects(subject_id),
    version INTEGER NOT NULL, state TEXT NOT NULL,
    submitted_severity TEXT, triaged_severity TEXT, bounty_usd TEXT,
    submitted_at TEXT, triaged_at TEXT, resolved_at TEXT NOT NULL,
    human_review_minutes TEXT NOT NULL, model_api_cost_usd TEXT NOT NULL,
    compute_cost_usd TEXT NOT NULL, analyst_note TEXT, operator_id TEXT NOT NULL,
    recorded_at TEXT NOT NULL, source_digest TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE, payload_digest TEXT NOT NULL,
    supersedes_outcome_event_id TEXT REFERENCES effectiveness_outcome_events(outcome_event_id),
    UNIQUE(subject_id, version)
);
CREATE INDEX IF NOT EXISTS idx_effectiveness_outcomes_latest
    ON effectiveness_outcome_events(subject_id, version DESC);
CREATE INDEX IF NOT EXISTS idx_effectiveness_outcomes_state
    ON effectiveness_outcome_events(state, resolved_at);

CREATE TABLE IF NOT EXISTS effectiveness_shadow_batches (
    batch_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, input_digest TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE, payload_digest TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS effectiveness_shadow_entries (
    batch_id TEXT NOT NULL REFERENCES effectiveness_shadow_batches(batch_id),
    opportunity_id TEXT NOT NULL, existing_rank INTEGER NOT NULL,
    existing_score TEXT NOT NULL, learned_rank INTEGER NOT NULL,
    learned_score TEXT NOT NULL, confidence TEXT NOT NULL, samples INTEGER NOT NULL,
    fallback_reason TEXT, PRIMARY KEY(batch_id, opportunity_id)
);
CREATE INDEX IF NOT EXISTS idx_effectiveness_shadow_opportunity
    ON effectiveness_shadow_entries(opportunity_id, batch_id);

CREATE TRIGGER IF NOT EXISTS effectiveness_subjects_no_update
BEFORE UPDATE ON effectiveness_subjects BEGIN SELECT RAISE(ABORT, 'immutable effectiveness ledger'); END;
CREATE TRIGGER IF NOT EXISTS effectiveness_subjects_no_delete
BEFORE DELETE ON effectiveness_subjects BEGIN SELECT RAISE(ABORT, 'immutable effectiveness ledger'); END;
CREATE TRIGGER IF NOT EXISTS effectiveness_facts_no_update
BEFORE UPDATE ON effectiveness_facts BEGIN SELECT RAISE(ABORT, 'immutable effectiveness ledger'); END;
CREATE TRIGGER IF NOT EXISTS effectiveness_facts_no_delete
BEFORE DELETE ON effectiveness_facts BEGIN SELECT RAISE(ABORT, 'immutable effectiveness ledger'); END;
CREATE TRIGGER IF NOT EXISTS effectiveness_outcomes_no_update
BEFORE UPDATE ON effectiveness_outcome_events BEGIN SELECT RAISE(ABORT, 'immutable effectiveness ledger'); END;
CREATE TRIGGER IF NOT EXISTS effectiveness_outcomes_no_delete
BEFORE DELETE ON effectiveness_outcome_events BEGIN SELECT RAISE(ABORT, 'immutable effectiveness ledger'); END;
CREATE TRIGGER IF NOT EXISTS effectiveness_shadow_batches_no_update
BEFORE UPDATE ON effectiveness_shadow_batches BEGIN SELECT RAISE(ABORT, 'immutable effectiveness ledger'); END;
CREATE TRIGGER IF NOT EXISTS effectiveness_shadow_batches_no_delete
BEFORE DELETE ON effectiveness_shadow_batches BEGIN SELECT RAISE(ABORT, 'immutable effectiveness ledger'); END;
CREATE TRIGGER IF NOT EXISTS effectiveness_shadow_entries_no_update
BEFORE UPDATE ON effectiveness_shadow_entries BEGIN SELECT RAISE(ABORT, 'immutable effectiveness ledger'); END;
CREATE TRIGGER IF NOT EXISTS effectiveness_shadow_entries_no_delete
BEFORE DELETE ON effectiveness_shadow_entries BEGIN SELECT RAISE(ABORT, 'immutable effectiveness ledger'); END;
"""
SQLITE_MIGRATION_VERSION = 1
SQLITE_MIGRATION_NAME = "effectiveness_measurement_v1"
SQLITE_MIGRATION_CHECKSUM = sha256(SQLITE_SCHEMA.encode()).hexdigest()

SQLITE_SCHEMA_V2 = """
ALTER TABLE effectiveness_subjects ADD COLUMN candidate_finding_id TEXT;
ALTER TABLE effectiveness_subjects ADD COLUMN human_decision_id TEXT;
ALTER TABLE effectiveness_subjects ADD COLUMN submission_id TEXT;
ALTER TABLE effectiveness_facts ADD COLUMN metadata_json TEXT;
ALTER TABLE effectiveness_facts ADD COLUMN model_version TEXT;

CREATE TABLE effectiveness_cost_observations (
    cost_record_id TEXT PRIMARY KEY,
    cost_observation_id TEXT NOT NULL UNIQUE,
    subject_id TEXT NOT NULL REFERENCES effectiveness_subjects(subject_id),
    campaign_id TEXT,
    model_api_cost_usd TEXT,
    scanner_compute_cost_usd TEXT,
    cloud_cost_usd TEXT,
    oast_cost_usd TEXT,
    browser_device_cost_usd TEXT,
    human_review_minutes TEXT,
    human_submission_minutes TEXT,
    human_other_minutes TEXT,
    human_hourly_rate_usd TEXT,
    calculation_version TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    operator_id TEXT NOT NULL,
    source_digest TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    payload_digest TEXT NOT NULL
);
CREATE INDEX idx_effectiveness_costs_subject
    ON effectiveness_cost_observations(subject_id, observed_at);
CREATE INDEX idx_effectiveness_costs_campaign
    ON effectiveness_cost_observations(campaign_id, observed_at);
CREATE TRIGGER effectiveness_costs_no_update
BEFORE UPDATE ON effectiveness_cost_observations
BEGIN SELECT RAISE(ABORT, 'immutable effectiveness ledger'); END;
CREATE TRIGGER effectiveness_costs_no_delete
BEFORE DELETE ON effectiveness_cost_observations
BEGIN SELECT RAISE(ABORT, 'immutable effectiveness ledger'); END;

ALTER TABLE effectiveness_outcome_events RENAME TO effectiveness_outcome_events_v1;
CREATE TABLE effectiveness_outcome_events (
    outcome_event_id TEXT PRIMARY KEY,
    subject_id TEXT NOT NULL REFERENCES effectiveness_subjects(subject_id),
    version INTEGER NOT NULL, state TEXT NOT NULL,
    submitted_severity TEXT, triaged_severity TEXT, bounty_usd TEXT,
    submitted_at TEXT, triaged_at TEXT, resolved_at TEXT,
    human_review_minutes TEXT, model_api_cost_usd TEXT,
    compute_cost_usd TEXT, analyst_note TEXT, operator_id TEXT NOT NULL,
    recorded_at TEXT NOT NULL, source_digest TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE, payload_digest TEXT NOT NULL,
    supersedes_outcome_event_id TEXT REFERENCES effectiveness_outcome_events(outcome_event_id),
    UNIQUE(subject_id, version)
);
INSERT INTO effectiveness_outcome_events SELECT * FROM effectiveness_outcome_events_v1;
DROP TABLE effectiveness_outcome_events_v1;
CREATE INDEX idx_effectiveness_outcomes_latest
    ON effectiveness_outcome_events(subject_id, version DESC);
CREATE INDEX idx_effectiveness_outcomes_state
    ON effectiveness_outcome_events(state, resolved_at);
CREATE TRIGGER effectiveness_outcomes_no_update
BEFORE UPDATE ON effectiveness_outcome_events
BEGIN SELECT RAISE(ABORT, 'immutable effectiveness ledger'); END;
CREATE TRIGGER effectiveness_outcomes_no_delete
BEFORE DELETE ON effectiveness_outcome_events
BEGIN SELECT RAISE(ABORT, 'immutable effectiveness ledger'); END;
"""
SQLITE_MIGRATION_V2_VERSION = 2
SQLITE_MIGRATION_V2_NAME = "profitability_acceleration_v2_lineage_costs"
SQLITE_MIGRATION_V2_CHECKSUM = sha256(SQLITE_SCHEMA_V2.encode()).hexdigest()

SQLITE_SCHEMA_V3 = """
ALTER TABLE effectiveness_shadow_entries ADD COLUMN actual_selected INTEGER;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN shadow_would_select INTEGER;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN economics_status TEXT;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN stop_loss_recommendation TEXT;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN allocation_mode TEXT;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN p_duplicate TEXT;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN ev_usd TEXT;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN ev_per_hour_usd TEXT;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN ev_per_request_usd TEXT;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN ev_per_compute_dollar TEXT;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN actual_realized_reward_usd TEXT;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN shadow_hypothetical_reward_usd TEXT;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN model_version TEXT;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN computed_at TEXT;
"""
SQLITE_MIGRATION_V3_VERSION = 3
SQLITE_MIGRATION_V3_NAME = "profitability_acceleration_v2_shadow_economics"
SQLITE_MIGRATION_V3_CHECKSUM = sha256(SQLITE_SCHEMA_V3.encode()).hexdigest()

SQLITE_SCHEMA_V4 = """
CREATE TABLE effectiveness_campaigns (
    campaign_id TEXT PRIMARY KEY, program_id TEXT NOT NULL,
    policy_snapshot_digest TEXT NOT NULL, scope_digest TEXT NOT NULL,
    selected_assets_json TEXT NOT NULL, allowed_techniques_json TEXT NOT NULL,
    time_budget_minutes TEXT NOT NULL, cost_budget_usd TEXT,
    starts_at TEXT NOT NULL, ends_at TEXT NOT NULL, operator_id TEXT NOT NULL,
    recorded_at TEXT NOT NULL, idempotency_key TEXT NOT NULL UNIQUE,
    payload_digest TEXT NOT NULL
);
CREATE TABLE effectiveness_campaign_events (
    campaign_event_id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES effectiveness_campaigns(campaign_id),
    event_type TEXT NOT NULL, observed_at TEXT NOT NULL, subject_id TEXT,
    metadata_json TEXT NOT NULL, source_digest TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE, payload_digest TEXT NOT NULL
);
CREATE INDEX idx_effectiveness_campaign_program
    ON effectiveness_campaigns(program_id, starts_at);
CREATE INDEX idx_effectiveness_campaign_events
    ON effectiveness_campaign_events(campaign_id, observed_at);
CREATE TRIGGER effectiveness_campaigns_no_update
BEFORE UPDATE ON effectiveness_campaigns
BEGIN SELECT RAISE(ABORT, 'immutable effectiveness ledger'); END;
CREATE TRIGGER effectiveness_campaigns_no_delete
BEFORE DELETE ON effectiveness_campaigns
BEGIN SELECT RAISE(ABORT, 'immutable effectiveness ledger'); END;
CREATE TRIGGER effectiveness_campaign_events_no_update
BEFORE UPDATE ON effectiveness_campaign_events
BEGIN SELECT RAISE(ABORT, 'immutable effectiveness ledger'); END;
CREATE TRIGGER effectiveness_campaign_events_no_delete
BEFORE DELETE ON effectiveness_campaign_events
BEGIN SELECT RAISE(ABORT, 'immutable effectiveness ledger'); END;
"""
SQLITE_MIGRATION_V4_VERSION = 4
SQLITE_MIGRATION_V4_NAME = "profitability_acceleration_v2_campaigns"
SQLITE_MIGRATION_V4_CHECKSUM = sha256(SQLITE_SCHEMA_V4.encode()).hexdigest()


def _flag(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _subject_values(subject: EffectivenessSubject) -> tuple[object, ...]:
    return (
        subject.subject_id, subject.run_id, subject.mission_id, subject.opportunity_id,
        subject.technique, subject.program_id, subject.asset_id, subject.weakness_family,
        subject.asset_class, subject.authentication_mode, subject.execution_mode,
        subject.evidence_digest, subject.source_digest, subject.created_at,
        subject.candidate_finding_id, subject.human_decision_id, subject.submission_id,
        payload_digest(subject),
    )


def _legacy_subject_digest(subject: EffectivenessSubject) -> str:
    names = (
        "subject_id", "run_id", "mission_id", "opportunity_id", "technique",
        "program_id", "asset_id", "weakness_family", "asset_class",
        "authentication_mode", "execution_mode", "evidence_digest", "source_digest",
        "created_at",
    )
    return payload_digest({name: getattr(subject, name) for name in names})


def _subject_from_row(row: Mapping[str, object]) -> EffectivenessSubject:
    values = {name: _text(row[name]) for name in (
        "subject_id", "run_id", "mission_id", "opportunity_id", "technique",
        "program_id", "asset_id", "weakness_family", "asset_class",
        "authentication_mode", "execution_mode", "evidence_digest", "source_digest",
        "created_at",
    )}
    for name in ("candidate_finding_id", "human_decision_id", "submission_id"):
        values[name] = _text(row[name])
    return EffectivenessSubject(**values)


def _text(value: object | None) -> str | None:
    if value is None:
        return None
    isoformat = getattr(value, "isoformat", None)
    return str(isoformat()) if callable(isoformat) else str(value)


def _fact_values(fact: EffectivenessFact) -> tuple[object, ...]:
    return (
        fact.fact_id, fact.subject_id, FactType(fact.fact_type).value, fact.observed_at,
        fact.source_digest, fact.idempotency_key,
        json.dumps(dict(fact.metadata or {}), sort_keys=True, separators=(",", ":")),
        fact.model_version, payload_digest(fact),
    )


def _fact_from_row(row: Mapping[str, object]) -> EffectivenessFact:
    raw_metadata = row["metadata_json"]
    metadata = (
        dict(raw_metadata) if isinstance(raw_metadata, Mapping)
        else json.loads(str(raw_metadata or "{}"))
    )
    return EffectivenessFact(
        fact_id=str(row["fact_id"]), subject_id=str(row["subject_id"]),
        fact_type=FactType(str(row["fact_type"])), observed_at=_text(row["observed_at"]),
        source_digest=str(row["source_digest"]), idempotency_key=str(row["idempotency_key"]),
        metadata=metadata, model_version=_text(row["model_version"]),
    )


def _legacy_fact_digest(fact: EffectivenessFact) -> str:
    names = ("fact_id", "subject_id", "fact_type", "observed_at", "source_digest", "idempotency_key")
    return payload_digest({name: getattr(fact, name) for name in names})


def _decimal_text(value: Decimal | None) -> str | None:
    return None if value is None else str(value)


def _cost_values(cost: CostObservation) -> tuple[object, ...]:
    return (
        cost.cost_observation_id, cost.subject_id, cost.campaign_id,
        _decimal_text(cost.model_api_cost_usd), _decimal_text(cost.scanner_compute_cost_usd),
        _decimal_text(cost.cloud_cost_usd), _decimal_text(cost.oast_cost_usd),
        _decimal_text(cost.browser_device_cost_usd), _decimal_text(cost.human_review_minutes),
        _decimal_text(cost.human_submission_minutes), _decimal_text(cost.human_other_minutes),
        _decimal_text(cost.human_hourly_rate_usd), cost.calculation_version,
        cost.observed_at, cost.operator_id, cost.source_digest, cost.idempotency_key,
    )


def _cost_from_row(row: Mapping[str, object]) -> CostRecord:
    def decimal(name: str) -> Decimal | None:
        return None if row[name] is None else Decimal(str(row[name]))

    payload = CostObservation(
        cost_observation_id=str(row["cost_observation_id"]),
        subject_id=str(row["subject_id"]), campaign_id=_text(row["campaign_id"]),
        model_api_cost_usd=decimal("model_api_cost_usd"),
        scanner_compute_cost_usd=decimal("scanner_compute_cost_usd"),
        cloud_cost_usd=decimal("cloud_cost_usd"), oast_cost_usd=decimal("oast_cost_usd"),
        browser_device_cost_usd=decimal("browser_device_cost_usd"),
        human_review_minutes=decimal("human_review_minutes"),
        human_submission_minutes=decimal("human_submission_minutes"),
        human_other_minutes=decimal("human_other_minutes"),
        human_hourly_rate_usd=decimal("human_hourly_rate_usd"),
        observed_at=_text(row["observed_at"]), operator_id=str(row["operator_id"]),
        source_digest=str(row["source_digest"]), idempotency_key=str(row["idempotency_key"]),
        calculation_version=str(row["calculation_version"]),
    )
    return CostRecord(
        cost_record_id=str(row["cost_record_id"]), recorded_at=_text(row["recorded_at"]),
        payload=payload,
    )


def _shadow_entry_values(batch_id: str, item: ShadowEntry) -> tuple[object, ...]:
    return (
        batch_id, item.opportunity_id, item.existing_rank, str(item.existing_score),
        item.learned_rank, str(item.learned_score), item.confidence.value, item.samples,
        item.fallback_reason, item.actual_selected, item.shadow_would_select,
        item.economics_status, item.stop_loss_recommendation, item.allocation_mode,
        _decimal_text(item.p_duplicate), _decimal_text(item.ev_usd),
        _decimal_text(item.ev_per_hour_usd), _decimal_text(item.ev_per_request_usd),
        _decimal_text(item.ev_per_compute_dollar),
        _decimal_text(item.actual_realized_reward_usd),
        _decimal_text(item.shadow_hypothetical_reward_usd), item.model_version,
        item.computed_at,
    )


def _shadow_entry_from_row(row: Mapping[str, object]) -> ShadowEntry:
    def decimal(name: str) -> Decimal | None:
        return None if row[name] is None else Decimal(str(row[name]))

    return ShadowEntry(
        opportunity_id=str(row["opportunity_id"]), existing_rank=int(row["existing_rank"]),
        existing_score=Decimal(str(row["existing_score"])),
        learned_rank=int(row["learned_rank"]),
        learned_score=Decimal(str(row["learned_score"])),
        confidence=ConfidenceState(str(row["confidence"])), samples=int(row["samples"]),
        fallback_reason=_text(row["fallback_reason"]),
        actual_selected=(None if row["actual_selected"] is None else bool(row["actual_selected"])),
        shadow_would_select=(None if row["shadow_would_select"] is None
                             else bool(row["shadow_would_select"])),
        economics_status=_text(row["economics_status"]),
        stop_loss_recommendation=_text(row["stop_loss_recommendation"]),
        allocation_mode=_text(row["allocation_mode"]), p_duplicate=decimal("p_duplicate"),
        ev_usd=decimal("ev_usd"), ev_per_hour_usd=decimal("ev_per_hour_usd"),
        ev_per_request_usd=decimal("ev_per_request_usd"),
        ev_per_compute_dollar=decimal("ev_per_compute_dollar"),
        actual_realized_reward_usd=decimal("actual_realized_reward_usd"),
        shadow_hypothetical_reward_usd=decimal("shadow_hypothetical_reward_usd"),
        model_version=_text(row["model_version"]), computed_at=_text(row["computed_at"]),
    )


def _legacy_shadow_batch_digest(batch: ShadowBatch) -> str:
    legacy_entries = [{
        name: getattr(item, name) for name in (
            "opportunity_id", "existing_rank", "existing_score", "learned_rank",
            "learned_score", "confidence", "samples", "fallback_reason",
        )
    } for item in batch.entries]
    return payload_digest({
        "batch_id": batch.batch_id, "created_at": batch.created_at,
        "input_digest": batch.input_digest, "idempotency_key": batch.idempotency_key,
        "entries": legacy_entries,
    })


def _campaign_values(campaign: CampaignInput) -> tuple[object, ...]:
    return (
        campaign.campaign_id, campaign.program_id, campaign.policy_snapshot_digest,
        campaign.scope_digest, json.dumps(campaign.selected_assets),
        json.dumps(campaign.allowed_techniques), str(campaign.time_budget_minutes),
        _decimal_text(campaign.cost_budget_usd), campaign.starts_at, campaign.ends_at,
        campaign.operator_id, campaign.idempotency_key,
    )


def _campaign_from_row(row: Mapping[str, object]) -> CampaignRecord:
    def array_value(name: str) -> tuple[str, ...]:
        raw = row[name]
        values = raw if isinstance(raw, (list, tuple)) else json.loads(str(raw))
        return tuple(str(item) for item in values)

    item = CampaignInput(
        campaign_id=str(row["campaign_id"]), program_id=str(row["program_id"]),
        policy_snapshot_digest=str(row["policy_snapshot_digest"]),
        scope_digest=str(row["scope_digest"]),
        selected_assets=array_value("selected_assets_json"),
        allowed_techniques=array_value("allowed_techniques_json"),
        time_budget_minutes=Decimal(str(row["time_budget_minutes"])),
        cost_budget_usd=(None if row["cost_budget_usd"] is None
                         else Decimal(str(row["cost_budget_usd"]))),
        starts_at=_text(row["starts_at"]), ends_at=_text(row["ends_at"]),
        operator_id=str(row["operator_id"]), idempotency_key=str(row["idempotency_key"]),
    )
    return CampaignRecord(recorded_at=_text(row["recorded_at"]), payload=item)


def _campaign_event_values(event: CampaignEvent) -> tuple[object, ...]:
    return (
        event.campaign_event_id, event.campaign_id, event.event_type, event.observed_at,
        event.subject_id,
        json.dumps(dict(event.metadata or {}), sort_keys=True, separators=(",", ":")),
        event.source_digest, event.idempotency_key, payload_digest(event),
    )


def _campaign_event_from_row(row: Mapping[str, object]) -> CampaignEvent:
    raw = row["metadata_json"]
    metadata = dict(raw) if isinstance(raw, Mapping) else json.loads(str(raw or "{}"))
    return CampaignEvent(
        campaign_event_id=str(row["campaign_event_id"]), campaign_id=str(row["campaign_id"]),
        event_type=str(row["event_type"]), observed_at=_text(row["observed_at"]),
        subject_id=_text(row["subject_id"]), metadata=metadata,
        source_digest=str(row["source_digest"]), idempotency_key=str(row["idempotency_key"]),
    )


def _outcome_payload_values(outcome: OutcomeInput) -> tuple[object, ...]:
    return (
        OutcomeState(outcome.state).value, outcome.submitted_severity,
        outcome.triaged_severity,
        None if outcome.bounty_usd is None else str(outcome.bounty_usd),
        outcome.submitted_at, outcome.triaged_at, outcome.resolved_at,
        _decimal_text(outcome.human_review_minutes), _decimal_text(outcome.model_api_cost_usd),
        _decimal_text(outcome.compute_cost_usd), outcome.analyst_note, outcome.operator_id,
        outcome.source_digest, outcome.idempotency_key,
        outcome.supersedes_outcome_event_id,
    )


def _outcome_from_row(row: Mapping[str, object]) -> OutcomeRecord:
    item = OutcomeInput(
        subject_id=str(row["subject_id"]), state=OutcomeState(str(row["state"])),
        submitted_severity=row["submitted_severity"], triaged_severity=row["triaged_severity"],
        bounty_usd=None if row["bounty_usd"] is None else Decimal(str(row["bounty_usd"])),
        submitted_at=_text(row["submitted_at"]), triaged_at=_text(row["triaged_at"]),
        resolved_at=_text(row["resolved_at"]),
        human_review_minutes=(None if row["human_review_minutes"] is None
                              else Decimal(str(row["human_review_minutes"]))),
        model_api_cost_usd=(None if row["model_api_cost_usd"] is None
                            else Decimal(str(row["model_api_cost_usd"]))),
        compute_cost_usd=(None if row["compute_cost_usd"] is None
                          else Decimal(str(row["compute_cost_usd"]))),
        analyst_note=row["analyst_note"], operator_id=str(row["operator_id"]),
        source_digest=str(row["source_digest"]), idempotency_key=str(row["idempotency_key"]),
        supersedes_outcome_event_id=row["supersedes_outcome_event_id"],
    )
    return OutcomeRecord(
        outcome_event_id=str(row["outcome_event_id"]), version=int(row["version"]),
        recorded_at=_text(row["recorded_at"]), payload=item,
    )


class SQLiteEffectivenessRepository:
    """SQLite semantic mirror for tests and development; never production authority."""

    authoritative = False

    def __init__(
        self, path: str | Path = ":memory:", *, production: bool | None = None,
    ) -> None:
        if production is None:
            production = _flag(os.environ.get("AEGIS_PRODUCTION"))
        if production:
            raise EffectivenessStorageStateError(
                "SQLite effectiveness backend is non-authoritative and forbidden with AEGIS_PRODUCTION=1"
            )
        self.path = str(path)
        self._conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA busy_timeout = 30000")
        if self.path != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.executescript(SQLITE_SCHEMA)
        row = self._conn.execute(
            "SELECT name,checksum FROM effectiveness_schema_migrations WHERE version=?",
            (SQLITE_MIGRATION_VERSION,),
        ).fetchone()
        if row is not None and row["checksum"] != SQLITE_MIGRATION_CHECKSUM:
            raise EffectivenessConflictError("effectiveness migration checksum mismatch")
        if row is None:
            self._conn.execute(
                "INSERT INTO effectiveness_schema_migrations VALUES (?,?,?,?)",
                (SQLITE_MIGRATION_VERSION, SQLITE_MIGRATION_NAME,
                 SQLITE_MIGRATION_CHECKSUM, utc_now()),
            )
        row = self._conn.execute(
            "SELECT name,checksum FROM effectiveness_schema_migrations WHERE version=?",
            (SQLITE_MIGRATION_V2_VERSION,),
        ).fetchone()
        if row is not None and row["checksum"] != SQLITE_MIGRATION_V2_CHECKSUM:
            raise EffectivenessConflictError("effectiveness migration checksum mismatch")
        if row is None:
            self._conn.executescript(SQLITE_SCHEMA_V2)
            self._conn.execute(
                "INSERT INTO effectiveness_schema_migrations VALUES (?,?,?,?)",
                (SQLITE_MIGRATION_V2_VERSION, SQLITE_MIGRATION_V2_NAME,
                 SQLITE_MIGRATION_V2_CHECKSUM, utc_now()),
            )
        row = self._conn.execute(
            "SELECT name,checksum FROM effectiveness_schema_migrations WHERE version=?",
            (SQLITE_MIGRATION_V3_VERSION,),
        ).fetchone()
        if row is not None and row["checksum"] != SQLITE_MIGRATION_V3_CHECKSUM:
            raise EffectivenessConflictError("effectiveness migration checksum mismatch")
        if row is None:
            self._conn.executescript(SQLITE_SCHEMA_V3)
            self._conn.execute(
                "INSERT INTO effectiveness_schema_migrations VALUES (?,?,?,?)",
                (SQLITE_MIGRATION_V3_VERSION, SQLITE_MIGRATION_V3_NAME,
                 SQLITE_MIGRATION_V3_CHECKSUM, utc_now()),
            )
        row = self._conn.execute(
            "SELECT name,checksum FROM effectiveness_schema_migrations WHERE version=?",
            (SQLITE_MIGRATION_V4_VERSION,),
        ).fetchone()
        if row is not None and row["checksum"] != SQLITE_MIGRATION_V4_CHECKSUM:
            raise EffectivenessConflictError("effectiveness migration checksum mismatch")
        if row is None:
            self._conn.executescript(SQLITE_SCHEMA_V4)
            self._conn.execute(
                "INSERT INTO effectiveness_schema_migrations VALUES (?,?,?,?)",
                (SQLITE_MIGRATION_V4_VERSION, SQLITE_MIGRATION_V4_NAME,
                 SQLITE_MIGRATION_V4_CHECKSUM, utc_now()),
            )

    def close(self) -> None:
        self._conn.close()

    def record_subject(
        self, subject: EffectivenessSubject, facts: Iterable[EffectivenessFact] = (),
    ) -> bool:
        facts = tuple(facts)
        if any(fact.subject_id != subject.subject_id for fact in facts):
            raise ValueError("all lifecycle facts must reference the inserted subject")
        digest = payload_digest(subject)
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            existing = self._conn.execute(
                "SELECT payload_digest FROM effectiveness_subjects WHERE subject_id=?",
                (subject.subject_id,),
            ).fetchone()
            if existing is not None:
                if existing[0] not in {digest, _legacy_subject_digest(subject)}:
                    raise EffectivenessConflictError("subject identity already has different content")
                self._conn.commit()
                return False
            self._conn.execute(
                "INSERT INTO effectiveness_subjects (subject_id,run_id,mission_id,"
                "opportunity_id,technique,program_id,asset_id,weakness_family,asset_class,"
                "authentication_mode,execution_mode,evidence_digest,source_digest,created_at,"
                "candidate_finding_id,human_decision_id,submission_id,payload_digest) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", _subject_values(subject),
            )
            for fact in facts:
                self._insert_fact(fact)
            self._conn.commit()
            return True
        except Exception:
            self._conn.rollback()
            raise

    def _insert_fact(self, fact: EffectivenessFact) -> bool:
        digest = payload_digest(fact)
        row = self._conn.execute(
            "SELECT payload_digest FROM effectiveness_facts WHERE idempotency_key=?",
            (fact.idempotency_key,),
        ).fetchone()
        if row is not None:
            if row[0] not in {digest, _legacy_fact_digest(fact)}:
                raise EffectivenessConflictError("fact idempotency key has different content")
            return False
        self._conn.execute(
            "INSERT INTO effectiveness_facts (fact_id,subject_id,fact_type,observed_at,"
            "source_digest,idempotency_key,metadata_json,model_version,payload_digest) "
            "VALUES (?,?,?,?,?,?,?,?,?)", _fact_values(fact),
        )
        return True

    def record_fact(self, fact: EffectivenessFact) -> bool:
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            if self.subject(fact.subject_id) is None:
                raise KeyError(f"unknown effectiveness subject {fact.subject_id}")
            inserted = self._insert_fact(fact)
            self._conn.commit()
            return inserted
        except Exception:
            self._conn.rollback()
            raise

    def subject(self, subject_id: str) -> EffectivenessSubject | None:
        row = self._conn.execute(
            "SELECT * FROM effectiveness_subjects WHERE subject_id=?", (subject_id,),
        ).fetchone()
        return _subject_from_row(row) if row is not None else None

    def subjects(self) -> tuple[EffectivenessSubject, ...]:
        rows = self._conn.execute(
            "SELECT * FROM effectiveness_subjects ORDER BY created_at,subject_id"
        ).fetchall()
        return tuple(_subject_from_row(row) for row in rows)

    def facts(self) -> tuple[EffectivenessFact, ...]:
        rows = self._conn.execute(
            "SELECT * FROM effectiveness_facts ORDER BY observed_at,fact_id"
        ).fetchall()
        return tuple(_fact_from_row(row) for row in rows)

    def record_cost(self, cost: CostObservation) -> tuple[CostRecord, bool]:
        digest = payload_digest(cost)
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            if self.subject(cost.subject_id) is None:
                raise KeyError(f"unknown effectiveness subject {cost.subject_id}")
            existing = self._conn.execute(
                "SELECT * FROM effectiveness_cost_observations WHERE idempotency_key=?",
                (cost.idempotency_key,),
            ).fetchone()
            if existing is not None:
                if existing["payload_digest"] != digest:
                    raise EffectivenessConflictError("cost idempotency key has different content")
                self._conn.commit()
                return _cost_from_row(existing), False
            record_id = f"cost-record-{payload_digest({'key': cost.idempotency_key})[:24]}"
            recorded_at = utc_now()
            self._conn.execute(
                "INSERT INTO effectiveness_cost_observations VALUES "
                "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (record_id, *_cost_values(cost)[:14], recorded_at, *_cost_values(cost)[14:], digest),
            )
            row = self._conn.execute(
                "SELECT * FROM effectiveness_cost_observations WHERE cost_record_id=?",
                (record_id,),
            ).fetchone()
            self._conn.commit()
            return _cost_from_row(row), True
        except Exception:
            self._conn.rollback()
            raise

    def costs(self, subject_id: str | None = None) -> tuple[CostRecord, ...]:
        if subject_id is None:
            rows = self._conn.execute(
                "SELECT * FROM effectiveness_cost_observations "
                "ORDER BY observed_at,cost_record_id"
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM effectiveness_cost_observations WHERE subject_id=? "
                "ORDER BY observed_at,cost_record_id", (subject_id,),
            ).fetchall()
        return tuple(_cost_from_row(row) for row in rows)

    def record_campaign(self, campaign: CampaignInput) -> tuple[CampaignRecord, bool]:
        digest = payload_digest(campaign)
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            existing = self._conn.execute(
                "SELECT * FROM effectiveness_campaigns WHERE idempotency_key=?",
                (campaign.idempotency_key,),
            ).fetchone()
            if existing is not None:
                if existing["payload_digest"] != digest:
                    raise EffectivenessConflictError("campaign idempotency key has different content")
                self._conn.commit()
                return _campaign_from_row(existing), False
            recorded_at = utc_now()
            self._conn.execute(
                "INSERT INTO effectiveness_campaigns VALUES ("
                + ",".join(["?"] * 14) + ")",
                (*_campaign_values(campaign)[:11], recorded_at,
                 _campaign_values(campaign)[11], digest),
            )
            row = self._conn.execute(
                "SELECT * FROM effectiveness_campaigns WHERE campaign_id=?",
                (campaign.campaign_id,),
            ).fetchone()
            self._conn.commit()
            return _campaign_from_row(row), True
        except Exception:
            self._conn.rollback()
            raise

    def campaigns(self) -> tuple[CampaignRecord, ...]:
        rows = self._conn.execute(
            "SELECT * FROM effectiveness_campaigns ORDER BY starts_at,campaign_id"
        ).fetchall()
        return tuple(_campaign_from_row(row) for row in rows)

    def record_campaign_event(self, event: CampaignEvent) -> bool:
        digest = payload_digest(event)
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            existing = self._conn.execute(
                "SELECT payload_digest FROM effectiveness_campaign_events "
                "WHERE idempotency_key=?", (event.idempotency_key,),
            ).fetchone()
            if existing is not None:
                if existing["payload_digest"] != digest:
                    raise EffectivenessConflictError(
                        "campaign event idempotency key has different content"
                    )
                self._conn.commit()
                return False
            self._conn.execute(
                "INSERT INTO effectiveness_campaign_events VALUES (?,?,?,?,?,?,?,?,?)",
                _campaign_event_values(event),
            )
            self._conn.commit()
            return True
        except Exception:
            self._conn.rollback()
            raise

    def campaign_events(self, campaign_id: str) -> tuple[CampaignEvent, ...]:
        rows = self._conn.execute(
            "SELECT * FROM effectiveness_campaign_events WHERE campaign_id=? "
            "ORDER BY observed_at,campaign_event_id", (campaign_id,),
        ).fetchall()
        return tuple(_campaign_event_from_row(row) for row in rows)

    def record_outcome(self, outcome: OutcomeInput) -> tuple[OutcomeRecord, bool]:
        digest = payload_digest(outcome)
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            if self.subject(outcome.subject_id) is None:
                raise KeyError(f"unknown effectiveness subject {outcome.subject_id}")
            existing = self._conn.execute(
                "SELECT * FROM effectiveness_outcome_events WHERE idempotency_key=?",
                (outcome.idempotency_key,),
            ).fetchone()
            if existing is not None:
                if existing["payload_digest"] != digest:
                    raise EffectivenessConflictError("outcome idempotency key has different content")
                self._conn.commit()
                return _outcome_from_row(existing), False
            latest = self._conn.execute(
                "SELECT * FROM effectiveness_outcome_events WHERE subject_id=? "
                "ORDER BY version DESC LIMIT 1", (outcome.subject_id,),
            ).fetchone()
            if latest is None:
                if outcome.supersedes_outcome_event_id is not None:
                    raise EffectivenessConflictError("initial outcome cannot supersede another event")
                version = 1
            else:
                if outcome.supersedes_outcome_event_id != latest["outcome_event_id"]:
                    raise EffectivenessConflictError(
                        "correction must explicitly supersede the latest outcome event"
                    )
                version = int(latest["version"]) + 1
            event_id = f"outcome-{payload_digest({'key': outcome.idempotency_key})[:24]}"
            recorded_at = utc_now()
            self._conn.execute(
                "INSERT INTO effectiveness_outcome_events VALUES "
                "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    event_id, outcome.subject_id, version, *_outcome_payload_values(outcome)[:12],
                    recorded_at, *_outcome_payload_values(outcome)[12:14], digest,
                    outcome.supersedes_outcome_event_id,
                ),
            )
            row = self._conn.execute(
                "SELECT * FROM effectiveness_outcome_events WHERE outcome_event_id=?", (event_id,),
            ).fetchone()
            self._conn.commit()
            return _outcome_from_row(row), True
        except Exception:
            self._conn.rollback()
            raise

    def outcome_history(self, subject_id: str) -> tuple[OutcomeRecord, ...]:
        rows = self._conn.execute(
            "SELECT * FROM effectiveness_outcome_events WHERE subject_id=? ORDER BY version",
            (subject_id,),
        ).fetchall()
        return tuple(_outcome_from_row(row) for row in rows)

    def latest_outcomes(self) -> tuple[OutcomeRecord, ...]:
        rows = self._conn.execute(
            "SELECT o.* FROM effectiveness_outcome_events o JOIN "
            "(SELECT subject_id,MAX(version) version FROM effectiveness_outcome_events "
            "GROUP BY subject_id) latest ON latest.subject_id=o.subject_id "
            "AND latest.version=o.version ORDER BY o.resolved_at,o.outcome_event_id"
        ).fetchall()
        return tuple(_outcome_from_row(row) for row in rows)

    def record_shadow_batch(self, batch: ShadowBatch) -> bool:
        digest = payload_digest(batch)
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            existing = self._conn.execute(
                "SELECT payload_digest FROM effectiveness_shadow_batches WHERE idempotency_key=?",
                (batch.idempotency_key,),
            ).fetchone()
            if existing is not None:
                if existing[0] not in {digest, _legacy_shadow_batch_digest(batch)}:
                    raise EffectivenessConflictError("shadow idempotency key has different content")
                self._conn.commit()
                return False
            self._conn.execute(
                "INSERT INTO effectiveness_shadow_batches VALUES (?,?,?,?,?)",
                (batch.batch_id, batch.created_at, batch.input_digest, batch.idempotency_key, digest),
            )
            self._conn.executemany(
                "INSERT INTO effectiveness_shadow_entries VALUES ("
                + ",".join(["?"] * 23) + ")",
                [_shadow_entry_values(batch.batch_id, item) for item in batch.entries],
            )
            self._conn.commit()
            return True
        except Exception:
            self._conn.rollback()
            raise

    def shadow_batches(self) -> tuple[ShadowBatch, ...]:
        batches = self._conn.execute(
            "SELECT * FROM effectiveness_shadow_batches ORDER BY created_at,batch_id"
        ).fetchall()
        output = []
        for batch in batches:
            rows = self._conn.execute(
                "SELECT * FROM effectiveness_shadow_entries WHERE batch_id=? "
                "ORDER BY existing_rank,opportunity_id", (batch["batch_id"],),
            ).fetchall()
            entries = tuple(_shadow_entry_from_row(row) for row in rows)
            output.append(ShadowBatch(
                batch_id=batch["batch_id"], created_at=batch["created_at"],
                input_digest=batch["input_digest"], idempotency_key=batch["idempotency_key"],
                entries=entries,
            ))
        return tuple(output)


def open_effectiveness_repository(
    *, backend: str, location: str, env: Mapping[str, str] | None = None,
) -> EffectivenessRepository:
    source = os.environ if env is None else env
    production = _flag(source.get("AEGIS_PRODUCTION"))
    normalized = backend.strip().lower()
    if normalized == "sqlite":
        return SQLiteEffectivenessRepository(location, production=production)
    if normalized != "postgresql":
        raise EffectivenessStorageStateError(f"unsupported effectiveness backend: {backend}")
    try:
        from .postgres import PostgresEffectivenessRepository

        return PostgresEffectivenessRepository(location)
    except EffectivenessError:
        raise
    except Exception as exc:
        raise EffectivenessUnavailableError(
            "authoritative PostgreSQL effectiveness backend is unavailable"
        ) from exc
