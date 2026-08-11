"""Repository contract and non-authoritative SQLite implementation."""

from __future__ import annotations

import os
import sqlite3
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from typing import Iterable, Mapping, Protocol

from .models import (
    ConfidenceState,
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


def _flag(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _subject_values(subject: EffectivenessSubject) -> tuple[object, ...]:
    return (
        subject.subject_id, subject.run_id, subject.mission_id, subject.opportunity_id,
        subject.technique, subject.program_id, subject.asset_id, subject.weakness_family,
        subject.asset_class, subject.authentication_mode, subject.execution_mode,
        subject.evidence_digest, subject.source_digest, subject.created_at,
        payload_digest(subject),
    )


def _subject_from_row(row: Mapping[str, object]) -> EffectivenessSubject:
    return EffectivenessSubject(**{name: _text(row[name]) for name in (
        "subject_id", "run_id", "mission_id", "opportunity_id", "technique",
        "program_id", "asset_id", "weakness_family", "asset_class",
        "authentication_mode", "execution_mode", "evidence_digest", "source_digest",
        "created_at",
    )})


def _text(value: object | None) -> str | None:
    if value is None:
        return None
    isoformat = getattr(value, "isoformat", None)
    return str(isoformat()) if callable(isoformat) else str(value)


def _fact_values(fact: EffectivenessFact) -> tuple[object, ...]:
    return (
        fact.fact_id, fact.subject_id, FactType(fact.fact_type).value, fact.observed_at,
        fact.source_digest, fact.idempotency_key, payload_digest(fact),
    )


def _outcome_payload_values(outcome: OutcomeInput) -> tuple[object, ...]:
    return (
        OutcomeState(outcome.state).value, outcome.submitted_severity,
        outcome.triaged_severity,
        None if outcome.bounty_usd is None else str(outcome.bounty_usd),
        outcome.submitted_at, outcome.triaged_at, outcome.resolved_at,
        str(outcome.human_review_minutes), str(outcome.model_api_cost_usd),
        str(outcome.compute_cost_usd), outcome.analyst_note, outcome.operator_id,
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
        human_review_minutes=Decimal(str(row["human_review_minutes"])),
        model_api_cost_usd=Decimal(str(row["model_api_cost_usd"])),
        compute_cost_usd=Decimal(str(row["compute_cost_usd"])),
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
                if existing[0] != digest:
                    raise EffectivenessConflictError("subject identity already has different content")
                self._conn.commit()
                return False
            self._conn.execute(
                "INSERT INTO effectiveness_subjects VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                _subject_values(subject),
            )
            for fact in facts:
                self._insert_fact(fact)
            self._conn.commit()
            return True
        except Exception:
            self._conn.rollback()
            raise

    def _insert_fact(self, fact: EffectivenessFact) -> None:
        digest = payload_digest(fact)
        row = self._conn.execute(
            "SELECT payload_digest FROM effectiveness_facts WHERE idempotency_key=?",
            (fact.idempotency_key,),
        ).fetchone()
        if row is not None:
            if row[0] != digest:
                raise EffectivenessConflictError("fact idempotency key has different content")
            return
        self._conn.execute(
            "INSERT INTO effectiveness_facts VALUES (?,?,?,?,?,?,?)", _fact_values(fact),
        )

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
        return tuple(EffectivenessFact(
            fact_id=row["fact_id"], subject_id=row["subject_id"],
            fact_type=FactType(row["fact_type"]), observed_at=row["observed_at"],
            source_digest=row["source_digest"], idempotency_key=row["idempotency_key"],
        ) for row in rows)

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
                if existing[0] != digest:
                    raise EffectivenessConflictError("shadow idempotency key has different content")
                self._conn.commit()
                return False
            self._conn.execute(
                "INSERT INTO effectiveness_shadow_batches VALUES (?,?,?,?,?)",
                (batch.batch_id, batch.created_at, batch.input_digest, batch.idempotency_key, digest),
            )
            self._conn.executemany(
                "INSERT INTO effectiveness_shadow_entries VALUES (?,?,?,?,?,?,?,?,?)",
                [(
                    batch.batch_id, item.opportunity_id, item.existing_rank,
                    str(item.existing_score), item.learned_rank, str(item.learned_score),
                    item.confidence.value, item.samples, item.fallback_reason,
                ) for item in batch.entries],
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
            entries = tuple(ShadowEntry(
                opportunity_id=row["opportunity_id"], existing_rank=row["existing_rank"],
                existing_score=Decimal(row["existing_score"]), learned_rank=row["learned_rank"],
                learned_score=Decimal(row["learned_score"]),
                confidence=ConfidenceState(row["confidence"]), samples=row["samples"],
                fallback_reason=row["fallback_reason"],
            ) for row in rows)
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
