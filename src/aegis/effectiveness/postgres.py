"""Authoritative PostgreSQL effectiveness ledger."""

from __future__ import annotations

import hashlib
from typing import Iterable

from .models import (
    CampaignEvent,
    CampaignInput,
    CampaignRecord,
    CostObservation,
    CostRecord,
    EffectivenessFact,
    EffectivenessSubject,
    OutcomeInput,
    OutcomeRecord,
    ShadowBatch,
    payload_digest,
    utc_now,
)
from .repository import (
    EffectivenessConflictError,
    _campaign_event_from_row,
    _campaign_event_values,
    _campaign_from_row,
    _campaign_values,
    _cost_from_row,
    _cost_values,
    _fact_from_row,
    _fact_values,
    _legacy_fact_digest,
    _legacy_shadow_batch_digest,
    _legacy_subject_digest,
    _outcome_from_row,
    _outcome_payload_values,
    _shadow_entry_from_row,
    _shadow_entry_values,
    _subject_from_row,
    _subject_values,
    _text,
)

POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS effectiveness_subjects (
    subject_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, mission_id TEXT NOT NULL,
    opportunity_id TEXT NOT NULL, technique TEXT NOT NULL, program_id TEXT NOT NULL,
    asset_id TEXT NOT NULL, weakness_family TEXT NOT NULL, asset_class TEXT NOT NULL,
    authentication_mode TEXT NOT NULL, execution_mode TEXT NOT NULL,
    evidence_digest TEXT NOT NULL, source_digest TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL, payload_digest TEXT NOT NULL,
    UNIQUE(run_id, mission_id, opportunity_id, technique)
);
CREATE INDEX IF NOT EXISTS idx_effectiveness_subject_dimensions
    ON effectiveness_subjects(technique, weakness_family, program_id, asset_class);
CREATE INDEX IF NOT EXISTS idx_effectiveness_subject_modes
    ON effectiveness_subjects(authentication_mode, execution_mode);

CREATE TABLE IF NOT EXISTS effectiveness_facts (
    fact_id TEXT PRIMARY KEY,
    subject_id TEXT NOT NULL REFERENCES effectiveness_subjects(subject_id),
    fact_type TEXT NOT NULL, observed_at TIMESTAMPTZ NOT NULL, source_digest TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE, payload_digest TEXT NOT NULL,
    UNIQUE(subject_id, fact_type, source_digest)
);
CREATE INDEX IF NOT EXISTS idx_effectiveness_facts_subject
    ON effectiveness_facts(subject_id, fact_type);

CREATE TABLE IF NOT EXISTS effectiveness_outcome_events (
    outcome_event_id TEXT PRIMARY KEY,
    subject_id TEXT NOT NULL REFERENCES effectiveness_subjects(subject_id),
    version INTEGER NOT NULL CHECK(version > 0), state TEXT NOT NULL,
    submitted_severity TEXT, triaged_severity TEXT, bounty_usd NUMERIC,
    submitted_at TIMESTAMPTZ, triaged_at TIMESTAMPTZ, resolved_at TIMESTAMPTZ NOT NULL,
    human_review_minutes NUMERIC NOT NULL CHECK(human_review_minutes >= 0),
    model_api_cost_usd NUMERIC NOT NULL CHECK(model_api_cost_usd >= 0),
    compute_cost_usd NUMERIC NOT NULL CHECK(compute_cost_usd >= 0),
    analyst_note TEXT, operator_id TEXT NOT NULL, recorded_at TIMESTAMPTZ NOT NULL,
    source_digest TEXT NOT NULL, idempotency_key TEXT NOT NULL UNIQUE,
    payload_digest TEXT NOT NULL,
    supersedes_outcome_event_id TEXT REFERENCES effectiveness_outcome_events(outcome_event_id),
    UNIQUE(subject_id, version)
);
CREATE INDEX IF NOT EXISTS idx_effectiveness_outcomes_latest
    ON effectiveness_outcome_events(subject_id, version DESC);
CREATE INDEX IF NOT EXISTS idx_effectiveness_outcomes_state
    ON effectiveness_outcome_events(state, resolved_at);

CREATE TABLE IF NOT EXISTS effectiveness_shadow_batches (
    batch_id TEXT PRIMARY KEY, created_at TIMESTAMPTZ NOT NULL, input_digest TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE, payload_digest TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS effectiveness_shadow_entries (
    batch_id TEXT NOT NULL REFERENCES effectiveness_shadow_batches(batch_id),
    opportunity_id TEXT NOT NULL, existing_rank INTEGER NOT NULL CHECK(existing_rank > 0),
    existing_score NUMERIC NOT NULL, learned_rank INTEGER NOT NULL CHECK(learned_rank > 0),
    learned_score NUMERIC NOT NULL, confidence TEXT NOT NULL, samples INTEGER NOT NULL,
    fallback_reason TEXT, PRIMARY KEY(batch_id, opportunity_id)
);
CREATE INDEX IF NOT EXISTS idx_effectiveness_shadow_opportunity
    ON effectiveness_shadow_entries(opportunity_id, batch_id);

CREATE OR REPLACE FUNCTION reject_effectiveness_mutation() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'immutable effectiveness ledger'; END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS effectiveness_subjects_immutable ON effectiveness_subjects;
CREATE TRIGGER effectiveness_subjects_immutable BEFORE UPDATE OR DELETE ON effectiveness_subjects
FOR EACH ROW EXECUTE FUNCTION reject_effectiveness_mutation();
DROP TRIGGER IF EXISTS effectiveness_facts_immutable ON effectiveness_facts;
CREATE TRIGGER effectiveness_facts_immutable BEFORE UPDATE OR DELETE ON effectiveness_facts
FOR EACH ROW EXECUTE FUNCTION reject_effectiveness_mutation();
DROP TRIGGER IF EXISTS effectiveness_outcomes_immutable ON effectiveness_outcome_events;
CREATE TRIGGER effectiveness_outcomes_immutable BEFORE UPDATE OR DELETE ON effectiveness_outcome_events
FOR EACH ROW EXECUTE FUNCTION reject_effectiveness_mutation();
DROP TRIGGER IF EXISTS effectiveness_shadow_batches_immutable ON effectiveness_shadow_batches;
CREATE TRIGGER effectiveness_shadow_batches_immutable BEFORE UPDATE OR DELETE ON effectiveness_shadow_batches
FOR EACH ROW EXECUTE FUNCTION reject_effectiveness_mutation();
DROP TRIGGER IF EXISTS effectiveness_shadow_entries_immutable ON effectiveness_shadow_entries;
CREATE TRIGGER effectiveness_shadow_entries_immutable BEFORE UPDATE OR DELETE ON effectiveness_shadow_entries
FOR EACH ROW EXECUTE FUNCTION reject_effectiveness_mutation();
"""

_MIGRATION_VERSION = 1
_MIGRATION_NAME = "effectiveness_measurement_v1"
_MIGRATION_CHECKSUM = hashlib.sha256(POSTGRES_SCHEMA.encode()).hexdigest()
_MIGRATION_LOCK_ID = 8234110017

POSTGRES_SCHEMA_V2 = """
ALTER TABLE effectiveness_subjects ADD COLUMN IF NOT EXISTS candidate_finding_id TEXT;
ALTER TABLE effectiveness_subjects ADD COLUMN IF NOT EXISTS human_decision_id TEXT;
ALTER TABLE effectiveness_subjects ADD COLUMN IF NOT EXISTS submission_id TEXT;
ALTER TABLE effectiveness_facts ADD COLUMN IF NOT EXISTS metadata_json JSONB;
ALTER TABLE effectiveness_facts ADD COLUMN IF NOT EXISTS model_version TEXT;
ALTER TABLE effectiveness_outcome_events ALTER COLUMN resolved_at DROP NOT NULL;
ALTER TABLE effectiveness_outcome_events ALTER COLUMN human_review_minutes DROP NOT NULL;
ALTER TABLE effectiveness_outcome_events ALTER COLUMN model_api_cost_usd DROP NOT NULL;
ALTER TABLE effectiveness_outcome_events ALTER COLUMN compute_cost_usd DROP NOT NULL;

CREATE TABLE IF NOT EXISTS effectiveness_cost_observations (
    cost_record_id TEXT PRIMARY KEY,
    cost_observation_id TEXT NOT NULL UNIQUE,
    subject_id TEXT NOT NULL REFERENCES effectiveness_subjects(subject_id),
    campaign_id TEXT,
    model_api_cost_usd NUMERIC CHECK(model_api_cost_usd >= 0),
    scanner_compute_cost_usd NUMERIC CHECK(scanner_compute_cost_usd >= 0),
    cloud_cost_usd NUMERIC CHECK(cloud_cost_usd >= 0),
    oast_cost_usd NUMERIC CHECK(oast_cost_usd >= 0),
    browser_device_cost_usd NUMERIC CHECK(browser_device_cost_usd >= 0),
    human_review_minutes NUMERIC CHECK(human_review_minutes >= 0),
    human_submission_minutes NUMERIC CHECK(human_submission_minutes >= 0),
    human_other_minutes NUMERIC CHECK(human_other_minutes >= 0),
    human_hourly_rate_usd NUMERIC CHECK(human_hourly_rate_usd >= 0),
    calculation_version TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    operator_id TEXT NOT NULL,
    source_digest TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    payload_digest TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_effectiveness_costs_subject
    ON effectiveness_cost_observations(subject_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_effectiveness_costs_campaign
    ON effectiveness_cost_observations(campaign_id, observed_at);
DROP TRIGGER IF EXISTS effectiveness_costs_immutable ON effectiveness_cost_observations;
CREATE TRIGGER effectiveness_costs_immutable
BEFORE UPDATE OR DELETE ON effectiveness_cost_observations
FOR EACH ROW EXECUTE FUNCTION reject_effectiveness_mutation();
"""
_MIGRATION_V2_VERSION = 2
_MIGRATION_V2_NAME = "profitability_acceleration_v2_lineage_costs"
_MIGRATION_V2_CHECKSUM = hashlib.sha256(POSTGRES_SCHEMA_V2.encode()).hexdigest()

POSTGRES_SCHEMA_V3 = """
ALTER TABLE effectiveness_shadow_entries ADD COLUMN IF NOT EXISTS actual_selected BOOLEAN;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN IF NOT EXISTS shadow_would_select BOOLEAN;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN IF NOT EXISTS economics_status TEXT;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN IF NOT EXISTS stop_loss_recommendation TEXT;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN IF NOT EXISTS allocation_mode TEXT;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN IF NOT EXISTS p_duplicate NUMERIC;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN IF NOT EXISTS ev_usd NUMERIC;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN IF NOT EXISTS ev_per_hour_usd NUMERIC;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN IF NOT EXISTS ev_per_request_usd NUMERIC;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN IF NOT EXISTS ev_per_compute_dollar NUMERIC;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN IF NOT EXISTS actual_realized_reward_usd NUMERIC;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN IF NOT EXISTS shadow_hypothetical_reward_usd NUMERIC;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN IF NOT EXISTS model_version TEXT;
ALTER TABLE effectiveness_shadow_entries ADD COLUMN IF NOT EXISTS computed_at TIMESTAMPTZ;
"""
_MIGRATION_V3_VERSION = 3
_MIGRATION_V3_NAME = "profitability_acceleration_v2_shadow_economics"
_MIGRATION_V3_CHECKSUM = hashlib.sha256(POSTGRES_SCHEMA_V3.encode()).hexdigest()

POSTGRES_SCHEMA_V4 = """
CREATE TABLE IF NOT EXISTS effectiveness_campaigns (
    campaign_id TEXT PRIMARY KEY, program_id TEXT NOT NULL,
    policy_snapshot_digest TEXT NOT NULL, scope_digest TEXT NOT NULL,
    selected_assets_json JSONB NOT NULL, allowed_techniques_json JSONB NOT NULL,
    time_budget_minutes NUMERIC NOT NULL CHECK(time_budget_minutes >= 0),
    cost_budget_usd NUMERIC CHECK(cost_budget_usd >= 0),
    starts_at TIMESTAMPTZ NOT NULL, ends_at TIMESTAMPTZ NOT NULL,
    operator_id TEXT NOT NULL, recorded_at TIMESTAMPTZ NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE, payload_digest TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS effectiveness_campaign_events (
    campaign_event_id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES effectiveness_campaigns(campaign_id),
    event_type TEXT NOT NULL, observed_at TIMESTAMPTZ NOT NULL, subject_id TEXT,
    metadata_json JSONB NOT NULL, source_digest TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE, payload_digest TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_effectiveness_campaign_program
    ON effectiveness_campaigns(program_id, starts_at);
CREATE INDEX IF NOT EXISTS idx_effectiveness_campaign_events
    ON effectiveness_campaign_events(campaign_id, observed_at);
DROP TRIGGER IF EXISTS effectiveness_campaigns_immutable ON effectiveness_campaigns;
CREATE TRIGGER effectiveness_campaigns_immutable
BEFORE UPDATE OR DELETE ON effectiveness_campaigns
FOR EACH ROW EXECUTE FUNCTION reject_effectiveness_mutation();
DROP TRIGGER IF EXISTS effectiveness_campaign_events_immutable ON effectiveness_campaign_events;
CREATE TRIGGER effectiveness_campaign_events_immutable
BEFORE UPDATE OR DELETE ON effectiveness_campaign_events
FOR EACH ROW EXECUTE FUNCTION reject_effectiveness_mutation();
"""
_MIGRATION_V4_VERSION = 4
_MIGRATION_V4_NAME = "profitability_acceleration_v2_campaigns"
_MIGRATION_V4_CHECKSUM = hashlib.sha256(POSTGRES_SCHEMA_V4.encode()).hexdigest()


class PostgresEffectivenessRepository:
    authoritative = True

    def __init__(self, dsn: str, *, min_size: int = 1, max_size: int = 8) -> None:
        from psycopg.rows import dict_row
        from psycopg_pool import ConnectionPool

        self._pool = ConnectionPool(
            dsn, min_size=min_size, max_size=max_size,
            kwargs={"autocommit": True, "row_factory": dict_row}, open=True,
        )
        self._migrate()

    def _migrate(self) -> None:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_lock(%s)", (_MIGRATION_LOCK_ID,))
            try:
                cursor.execute(
                    "CREATE TABLE IF NOT EXISTS effectiveness_schema_migrations ("
                    "version INTEGER PRIMARY KEY,name TEXT NOT NULL,checksum TEXT NOT NULL,"
                    "applied_at TIMESTAMPTZ NOT NULL)"
                )
                cursor.execute(
                    "SELECT name,checksum FROM effectiveness_schema_migrations WHERE version=%s",
                    (_MIGRATION_VERSION,),
                )
                row = cursor.fetchone()
                if row is not None and row["checksum"] != _MIGRATION_CHECKSUM:
                    raise EffectivenessConflictError("effectiveness migration checksum mismatch")
                if row is None:
                    cursor.execute(POSTGRES_SCHEMA)
                    cursor.execute(
                        "INSERT INTO effectiveness_schema_migrations VALUES (%s,%s,%s,%s)",
                        (_MIGRATION_VERSION, _MIGRATION_NAME, _MIGRATION_CHECKSUM, utc_now()),
                    )
                cursor.execute(
                    "SELECT name,checksum FROM effectiveness_schema_migrations WHERE version=%s",
                    (_MIGRATION_V2_VERSION,),
                )
                row = cursor.fetchone()
                if row is not None and row["checksum"] != _MIGRATION_V2_CHECKSUM:
                    raise EffectivenessConflictError("effectiveness migration checksum mismatch")
                if row is None:
                    cursor.execute(POSTGRES_SCHEMA_V2)
                    cursor.execute(
                        "INSERT INTO effectiveness_schema_migrations VALUES (%s,%s,%s,%s)",
                        (_MIGRATION_V2_VERSION, _MIGRATION_V2_NAME,
                         _MIGRATION_V2_CHECKSUM, utc_now()),
                    )
                cursor.execute(
                    "SELECT name,checksum FROM effectiveness_schema_migrations WHERE version=%s",
                    (_MIGRATION_V3_VERSION,),
                )
                row = cursor.fetchone()
                if row is not None and row["checksum"] != _MIGRATION_V3_CHECKSUM:
                    raise EffectivenessConflictError("effectiveness migration checksum mismatch")
                if row is None:
                    cursor.execute(POSTGRES_SCHEMA_V3)
                    cursor.execute(
                        "INSERT INTO effectiveness_schema_migrations VALUES (%s,%s,%s,%s)",
                        (_MIGRATION_V3_VERSION, _MIGRATION_V3_NAME,
                         _MIGRATION_V3_CHECKSUM, utc_now()),
                    )
                cursor.execute(
                    "SELECT name,checksum FROM effectiveness_schema_migrations WHERE version=%s",
                    (_MIGRATION_V4_VERSION,),
                )
                row = cursor.fetchone()
                if row is not None and row["checksum"] != _MIGRATION_V4_CHECKSUM:
                    raise EffectivenessConflictError("effectiveness migration checksum mismatch")
                if row is None:
                    cursor.execute(POSTGRES_SCHEMA_V4)
                    cursor.execute(
                        "INSERT INTO effectiveness_schema_migrations VALUES (%s,%s,%s,%s)",
                        (_MIGRATION_V4_VERSION, _MIGRATION_V4_NAME,
                         _MIGRATION_V4_CHECKSUM, utc_now()),
                    )
            finally:
                cursor.execute("SELECT pg_advisory_unlock(%s)", (_MIGRATION_LOCK_ID,))

    def close(self) -> None:
        self._pool.close()

    def record_subject(
        self, subject: EffectivenessSubject, facts: Iterable[EffectivenessFact] = (),
    ) -> bool:
        facts = tuple(facts)
        if any(fact.subject_id != subject.subject_id for fact in facts):
            raise ValueError("all lifecycle facts must reference the inserted subject")
        digest = payload_digest(subject)
        with self._pool.connection() as connection, connection.transaction(), connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (subject.subject_id,))
            cursor.execute(
                "SELECT payload_digest FROM effectiveness_subjects WHERE subject_id=%s",
                (subject.subject_id,),
            )
            existing = cursor.fetchone()
            if existing is not None:
                if existing["payload_digest"] not in {digest, _legacy_subject_digest(subject)}:
                    raise EffectivenessConflictError("subject identity already has different content")
                return False
            cursor.execute(
                "INSERT INTO effectiveness_subjects (subject_id,run_id,mission_id,"
                "opportunity_id,technique,program_id,asset_id,weakness_family,asset_class,"
                "authentication_mode,execution_mode,evidence_digest,source_digest,created_at,"
                "candidate_finding_id,human_decision_id,submission_id,payload_digest) VALUES ("
                + ",".join(["%s"] * 18) + ")", _subject_values(subject),
            )
            for fact in facts:
                self._insert_fact(cursor, fact)
            return True

    @staticmethod
    def _insert_fact(cursor, fact: EffectivenessFact) -> bool:
        digest = payload_digest(fact)
        cursor.execute(
            "SELECT payload_digest FROM effectiveness_facts WHERE idempotency_key=%s",
            (fact.idempotency_key,),
        )
        existing = cursor.fetchone()
        if existing is not None:
            if existing["payload_digest"] not in {digest, _legacy_fact_digest(fact)}:
                raise EffectivenessConflictError("fact idempotency key has different content")
            return False
        cursor.execute(
            "INSERT INTO effectiveness_facts (fact_id,subject_id,fact_type,observed_at,"
            "source_digest,idempotency_key,metadata_json,model_version,payload_digest) VALUES ("
            + ",".join(["%s"] * 9) + ")",
            _fact_values(fact),
        )
        return True

    def record_fact(self, fact: EffectivenessFact) -> bool:
        with self._pool.connection() as connection, connection.transaction(), connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (fact.idempotency_key,))
            cursor.execute(
                "SELECT 1 FROM effectiveness_subjects WHERE subject_id=%s", (fact.subject_id,),
            )
            if cursor.fetchone() is None:
                raise KeyError(f"unknown effectiveness subject {fact.subject_id}")
            return self._insert_fact(cursor, fact)

    def subject(self, subject_id: str) -> EffectivenessSubject | None:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT * FROM effectiveness_subjects WHERE subject_id=%s", (subject_id,))
            row = cursor.fetchone()
        return _subject_from_row(row) if row is not None else None

    def subjects(self) -> tuple[EffectivenessSubject, ...]:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT * FROM effectiveness_subjects ORDER BY created_at,subject_id")
            rows = cursor.fetchall()
        return tuple(_subject_from_row(row) for row in rows)

    def facts(self) -> tuple[EffectivenessFact, ...]:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT * FROM effectiveness_facts ORDER BY observed_at,fact_id")
            rows = cursor.fetchall()
        return tuple(_fact_from_row(row) for row in rows)

    def record_cost(self, cost: CostObservation) -> tuple[CostRecord, bool]:
        digest = payload_digest(cost)
        with self._pool.connection() as connection, connection.transaction(), connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (cost.idempotency_key,))
            cursor.execute(
                "SELECT 1 FROM effectiveness_subjects WHERE subject_id=%s", (cost.subject_id,),
            )
            if cursor.fetchone() is None:
                raise KeyError(f"unknown effectiveness subject {cost.subject_id}")
            cursor.execute(
                "SELECT * FROM effectiveness_cost_observations WHERE idempotency_key=%s",
                (cost.idempotency_key,),
            )
            existing = cursor.fetchone()
            if existing is not None:
                if existing["payload_digest"] != digest:
                    raise EffectivenessConflictError("cost idempotency key has different content")
                return _cost_from_row(existing), False
            record_id = f"cost-record-{payload_digest({'key': cost.idempotency_key})[:24]}"
            recorded_at = utc_now()
            values = _cost_values(cost)
            cursor.execute(
                "INSERT INTO effectiveness_cost_observations VALUES ("
                + ",".join(["%s"] * 20) + ")",
                (record_id, *values[:14], recorded_at, *values[14:], digest),
            )
            cursor.execute(
                "SELECT * FROM effectiveness_cost_observations WHERE cost_record_id=%s",
                (record_id,),
            )
            return _cost_from_row(cursor.fetchone()), True

    def costs(self, subject_id: str | None = None) -> tuple[CostRecord, ...]:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            if subject_id is None:
                cursor.execute(
                    "SELECT * FROM effectiveness_cost_observations "
                    "ORDER BY observed_at,cost_record_id"
                )
            else:
                cursor.execute(
                    "SELECT * FROM effectiveness_cost_observations WHERE subject_id=%s "
                    "ORDER BY observed_at,cost_record_id", (subject_id,),
                )
            rows = cursor.fetchall()
        return tuple(_cost_from_row(row) for row in rows)

    def record_campaign(self, campaign: CampaignInput) -> tuple[CampaignRecord, bool]:
        digest = payload_digest(campaign)
        with self._pool.connection() as connection, connection.transaction(), connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (campaign.idempotency_key,))
            cursor.execute(
                "SELECT * FROM effectiveness_campaigns WHERE idempotency_key=%s",
                (campaign.idempotency_key,),
            )
            existing = cursor.fetchone()
            if existing is not None:
                if existing["payload_digest"] != digest:
                    raise EffectivenessConflictError("campaign idempotency key has different content")
                return _campaign_from_row(existing), False
            recorded_at = utc_now()
            values = _campaign_values(campaign)
            cursor.execute(
                "INSERT INTO effectiveness_campaigns VALUES ("
                + ",".join(["%s"] * 14) + ")",
                (*values[:11], recorded_at, values[11], digest),
            )
            cursor.execute(
                "SELECT * FROM effectiveness_campaigns WHERE campaign_id=%s",
                (campaign.campaign_id,),
            )
            return _campaign_from_row(cursor.fetchone()), True

    def campaigns(self) -> tuple[CampaignRecord, ...]:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT * FROM effectiveness_campaigns ORDER BY starts_at,campaign_id")
            rows = cursor.fetchall()
        return tuple(_campaign_from_row(row) for row in rows)

    def record_campaign_event(self, event: CampaignEvent) -> bool:
        digest = payload_digest(event)
        with self._pool.connection() as connection, connection.transaction(), connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (event.idempotency_key,))
            cursor.execute(
                "SELECT payload_digest FROM effectiveness_campaign_events "
                "WHERE idempotency_key=%s", (event.idempotency_key,),
            )
            existing = cursor.fetchone()
            if existing is not None:
                if existing["payload_digest"] != digest:
                    raise EffectivenessConflictError(
                        "campaign event idempotency key has different content"
                    )
                return False
            cursor.execute(
                "INSERT INTO effectiveness_campaign_events VALUES ("
                + ",".join(["%s"] * 9) + ")", _campaign_event_values(event),
            )
            return True

    def campaign_events(self, campaign_id: str) -> tuple[CampaignEvent, ...]:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM effectiveness_campaign_events WHERE campaign_id=%s "
                "ORDER BY observed_at,campaign_event_id", (campaign_id,),
            )
            rows = cursor.fetchall()
        return tuple(_campaign_event_from_row(row) for row in rows)

    def record_outcome(self, outcome: OutcomeInput) -> tuple[OutcomeRecord, bool]:
        digest = payload_digest(outcome)
        with self._pool.connection() as connection, connection.transaction(), connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (outcome.subject_id,))
            cursor.execute("SELECT 1 FROM effectiveness_subjects WHERE subject_id=%s", (outcome.subject_id,))
            if cursor.fetchone() is None:
                raise KeyError(f"unknown effectiveness subject {outcome.subject_id}")
            cursor.execute(
                "SELECT * FROM effectiveness_outcome_events WHERE idempotency_key=%s",
                (outcome.idempotency_key,),
            )
            existing = cursor.fetchone()
            if existing is not None:
                if existing["payload_digest"] != digest:
                    raise EffectivenessConflictError("outcome idempotency key has different content")
                return _outcome_from_row(existing), False
            cursor.execute(
                "SELECT * FROM effectiveness_outcome_events WHERE subject_id=%s "
                "ORDER BY version DESC LIMIT 1 FOR UPDATE", (outcome.subject_id,),
            )
            latest = cursor.fetchone()
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
            values = _outcome_payload_values(outcome)
            cursor.execute(
                "INSERT INTO effectiveness_outcome_events VALUES ("
                + ",".join(["%s"] * 20) + ")",
                (event_id, outcome.subject_id, version, *values[:12], recorded_at,
                 *values[12:14], digest, outcome.supersedes_outcome_event_id),
            )
            cursor.execute(
                "SELECT * FROM effectiveness_outcome_events WHERE outcome_event_id=%s", (event_id,),
            )
            return _outcome_from_row(cursor.fetchone()), True

    def outcome_history(self, subject_id: str) -> tuple[OutcomeRecord, ...]:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM effectiveness_outcome_events WHERE subject_id=%s ORDER BY version",
                (subject_id,),
            )
            rows = cursor.fetchall()
        return tuple(_outcome_from_row(row) for row in rows)

    def latest_outcomes(self) -> tuple[OutcomeRecord, ...]:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT DISTINCT ON (subject_id) * FROM effectiveness_outcome_events "
                "ORDER BY subject_id,version DESC"
            )
            rows = cursor.fetchall()
        return tuple(sorted((_outcome_from_row(row) for row in rows),
                            key=lambda item: (
                                item.payload.resolved_at or "", item.outcome_event_id,
                            )))

    def record_shadow_batch(self, batch: ShadowBatch) -> bool:
        digest = payload_digest(batch)
        with self._pool.connection() as connection, connection.transaction(), connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (batch.idempotency_key,))
            cursor.execute(
                "SELECT payload_digest FROM effectiveness_shadow_batches WHERE idempotency_key=%s",
                (batch.idempotency_key,),
            )
            existing = cursor.fetchone()
            if existing is not None:
                if existing["payload_digest"] not in {
                    digest, _legacy_shadow_batch_digest(batch),
                }:
                    raise EffectivenessConflictError("shadow idempotency key has different content")
                return False
            cursor.execute(
                "INSERT INTO effectiveness_shadow_batches VALUES (%s,%s,%s,%s,%s)",
                (batch.batch_id, batch.created_at, batch.input_digest, batch.idempotency_key, digest),
            )
            cursor.executemany(
                "INSERT INTO effectiveness_shadow_entries VALUES ("
                + ",".join(["%s"] * 23) + ")",
                [_shadow_entry_values(batch.batch_id, item) for item in batch.entries],
            )
            return True

    def shadow_batches(self) -> tuple[ShadowBatch, ...]:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT * FROM effectiveness_shadow_batches ORDER BY created_at,batch_id")
            batches = cursor.fetchall()
            output = []
            for batch in batches:
                cursor.execute(
                    "SELECT * FROM effectiveness_shadow_entries WHERE batch_id=%s "
                    "ORDER BY existing_rank,opportunity_id", (batch["batch_id"],),
                )
                entries = tuple(_shadow_entry_from_row(row) for row in cursor.fetchall())
                output.append(ShadowBatch(
                    batch_id=batch["batch_id"], created_at=_text(batch["created_at"]),
                    input_digest=batch["input_digest"],
                    idempotency_key=batch["idempotency_key"], entries=entries,
                ))
        return tuple(output)
