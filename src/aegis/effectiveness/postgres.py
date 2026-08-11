"""Authoritative PostgreSQL effectiveness ledger."""

from __future__ import annotations

import hashlib
from decimal import Decimal
from typing import Iterable

from .models import (
    ConfidenceState,
    EffectivenessFact,
    EffectivenessSubject,
    FactType,
    OutcomeInput,
    OutcomeRecord,
    ShadowBatch,
    ShadowEntry,
    payload_digest,
    utc_now,
)
from .repository import (
    EffectivenessConflictError,
    _fact_values,
    _outcome_from_row,
    _outcome_payload_values,
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
                if existing["payload_digest"] != digest:
                    raise EffectivenessConflictError("subject identity already has different content")
                return False
            cursor.execute(
                "INSERT INTO effectiveness_subjects VALUES ("
                + ",".join(["%s"] * 15) + ")", _subject_values(subject),
            )
            for fact in facts:
                self._insert_fact(cursor, fact)
            return True

    @staticmethod
    def _insert_fact(cursor, fact: EffectivenessFact) -> None:
        digest = payload_digest(fact)
        cursor.execute(
            "SELECT payload_digest FROM effectiveness_facts WHERE idempotency_key=%s",
            (fact.idempotency_key,),
        )
        existing = cursor.fetchone()
        if existing is not None:
            if existing["payload_digest"] != digest:
                raise EffectivenessConflictError("fact idempotency key has different content")
            return
        cursor.execute(
            "INSERT INTO effectiveness_facts VALUES (" + ",".join(["%s"] * 7) + ")",
            _fact_values(fact),
        )

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
        return tuple(EffectivenessFact(
            fact_id=row["fact_id"], subject_id=row["subject_id"],
            fact_type=FactType(row["fact_type"]), observed_at=_text(row["observed_at"]),
            source_digest=row["source_digest"], idempotency_key=row["idempotency_key"],
        ) for row in rows)

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
                            key=lambda item: (item.payload.resolved_at, item.outcome_event_id)))

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
                if existing["payload_digest"] != digest:
                    raise EffectivenessConflictError("shadow idempotency key has different content")
                return False
            cursor.execute(
                "INSERT INTO effectiveness_shadow_batches VALUES (%s,%s,%s,%s,%s)",
                (batch.batch_id, batch.created_at, batch.input_digest, batch.idempotency_key, digest),
            )
            cursor.executemany(
                "INSERT INTO effectiveness_shadow_entries VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                [(
                    batch.batch_id, item.opportunity_id, item.existing_rank,
                    item.existing_score, item.learned_rank, item.learned_score,
                    item.confidence.value, item.samples, item.fallback_reason,
                ) for item in batch.entries],
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
                entries = tuple(ShadowEntry(
                    opportunity_id=row["opportunity_id"], existing_rank=row["existing_rank"],
                    existing_score=Decimal(row["existing_score"]),
                    learned_rank=row["learned_rank"], learned_score=Decimal(row["learned_score"]),
                    confidence=ConfidenceState(row["confidence"]), samples=row["samples"],
                    fallback_reason=row["fallback_reason"],
                ) for row in cursor.fetchall())
                output.append(ShadowBatch(
                    batch_id=batch["batch_id"], created_at=_text(batch["created_at"]),
                    input_digest=batch["input_digest"],
                    idempotency_key=batch["idempotency_key"], entries=entries,
                ))
        return tuple(output)
