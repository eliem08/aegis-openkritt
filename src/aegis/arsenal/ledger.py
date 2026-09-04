"""Append-only arsenal coverage ledger with PostgreSQL production authority."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from typing import Any, Protocol

from .models import (
    ArsenalCoverageState,
    CapabilityCoverageRecord,
    CapabilityMode,
    ExecutionProofKind,
)


class CoverageStorageError(RuntimeError):
    pass


class CoverageConflictError(RuntimeError):
    pass


class CoverageRepository(Protocol):
    def record(self, value: CapabilityCoverageRecord) -> tuple[CapabilityCoverageRecord, bool]: ...
    def records(self) -> tuple[CapabilityCoverageRecord, ...]: ...
    def close(self) -> None: ...


def _canonical(value: CapabilityCoverageRecord) -> str:
    return json.dumps(value.document(), sort_keys=True, separators=(",", ":"))


def _digest(value: CapabilityCoverageRecord) -> str:
    return sha256(_canonical(value).encode()).hexdigest()


_COLUMNS = (
    "coverage_record_id,idempotency_key,capability_id,mode,tool_name,tool_version,"
    "technique_id,asset_classes,implementation_path,backend,backend_version,backend_health,"
    "policy_snapshot_digest,asset,authorization_decision,operator_approval_id,"
    "execution_grant_id,run_id,mission_id,task_id,executed,execution_timestamp,"
    "evidence_digest,result,finding_ids,error_or_block_reason,execution_error_class,"
    "negative_control_status,historical_evidence_invalid,schema_version,execution_metadata,"
    "payload_digest"
)


def _values(value: CapabilityCoverageRecord) -> tuple[Any, ...]:
    return (
        value.coverage_record_id, value.idempotency_key, value.capability_id,
        value.mode.value, value.tool_name, value.tool_version, value.technique_id,
        json.dumps(value.asset_classes), value.implementation_path, value.backend,
        value.backend_version, value.backend_health, value.policy_snapshot_digest,
        value.asset, value.authorization_decision, value.operator_approval_id,
        value.execution_grant_id, value.run_id, value.mission_id, value.task_id,
        value.executed, value.execution_timestamp, value.evidence_digest,
        value.result.value, json.dumps(value.finding_ids), value.error_or_block_reason,
        value.execution_error_class, value.negative_control_status,
        value.historical_evidence_invalid, value.schema_version,
        json.dumps(value.execution_metadata(), sort_keys=True, separators=(",", ":")),
        _digest(value),
    )


def _record(row: Any) -> CapabilityCoverageRecord:
    metadata = json.loads(row[30] or "{}")
    return CapabilityCoverageRecord(
        coverage_record_id=str(row[0]), idempotency_key=str(row[1]),
        capability_id=str(row[2]), mode=CapabilityMode(row[3]), tool_name=str(row[4]),
        tool_version=str(row[5]), technique_id=str(row[6]),
        asset_classes=tuple(json.loads(row[7])), implementation_path=str(row[8]),
        backend=str(row[9]), backend_version=str(row[10]), backend_health=str(row[11]),
        policy_snapshot_digest=str(row[12]), asset=str(row[13]),
        authorization_decision=str(row[14]), operator_approval_id=row[15],
        execution_grant_id=row[16], run_id=str(row[17]), mission_id=str(row[18]),
        task_id=str(row[19]), executed=bool(row[20]), execution_timestamp=row[21],
        evidence_digest=row[22], result=ArsenalCoverageState(row[23]),
        finding_ids=tuple(json.loads(row[24])), error_or_block_reason=str(row[25]),
        execution_error_class=row[26], negative_control_status=str(row[27]),
        historical_evidence_invalid=bool(row[28]), schema_version=int(row[29]),
        backend_execution_id=str(metadata.get("backend_execution_id") or ""),
        binary_path=str(metadata.get("binary_path") or ""),
        container_digest=str(metadata.get("container_digest") or ""),
        adapter_version=str(metadata.get("adapter_version") or ""),
        capability_ids=tuple(metadata.get("capability_ids") or ()),
        fixture_version=str(metadata.get("fixture_version") or ""),
        positive_fixture_digest=str(metadata.get("positive_fixture_digest") or ""),
        negative_fixture_digest=str(metadata.get("negative_fixture_digest") or ""),
        execution_started_at=str(metadata.get("execution_started_at") or ""),
        execution_completed_at=str(metadata.get("execution_completed_at") or ""),
        duration_ms=int(metadata.get("duration_ms") or 0),
        exit_code=metadata.get("exit_code"),
        stdout_digest=str(metadata.get("stdout_digest") or ""),
        stderr_digest=str(metadata.get("stderr_digest") or ""),
        parsed_result_digest=str(metadata.get("parsed_result_digest") or ""),
        positive_control_detected=metadata.get("positive_control_detected"),
        negative_control_clean=metadata.get("negative_control_clean"),
        supersedes_coverage_record_id=metadata.get("supersedes_coverage_record_id"),
        execution_proof_kind=ExecutionProofKind(
            metadata.get("execution_proof_kind") or ExecutionProofKind.LEGACY_UNVERIFIED.value
        ),
    )


SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS arsenal_coverage_records (
  coverage_record_id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  capability_id TEXT NOT NULL,
  mode TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  tool_version TEXT NOT NULL,
  technique_id TEXT NOT NULL,
  asset_classes TEXT NOT NULL,
  implementation_path TEXT NOT NULL,
  backend TEXT NOT NULL,
  backend_version TEXT NOT NULL,
  backend_health TEXT NOT NULL,
  policy_snapshot_digest TEXT NOT NULL,
  asset TEXT NOT NULL,
  authorization_decision TEXT NOT NULL,
  operator_approval_id TEXT,
  execution_grant_id TEXT,
  run_id TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  executed INTEGER NOT NULL,
  execution_timestamp TEXT,
  evidence_digest TEXT,
  result TEXT NOT NULL,
  finding_ids TEXT NOT NULL,
  error_or_block_reason TEXT NOT NULL,
  execution_error_class TEXT,
  negative_control_status TEXT NOT NULL,
  historical_evidence_invalid INTEGER NOT NULL,
  schema_version INTEGER NOT NULL,
  execution_metadata TEXT NOT NULL DEFAULT '{}',
  payload_digest TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_arsenal_coverage_capability
  ON arsenal_coverage_records(capability_id,mode,execution_timestamp);
CREATE INDEX IF NOT EXISTS idx_arsenal_coverage_run
  ON arsenal_coverage_records(run_id,mission_id,task_id);
CREATE TRIGGER IF NOT EXISTS arsenal_coverage_no_update
BEFORE UPDATE ON arsenal_coverage_records BEGIN SELECT RAISE(ABORT,'immutable coverage'); END;
CREATE TRIGGER IF NOT EXISTS arsenal_coverage_no_delete
BEFORE DELETE ON arsenal_coverage_records BEGIN SELECT RAISE(ABORT,'immutable coverage'); END;
"""


class SqliteCoverageRepository:
    def __init__(self, path: str | Path, *, production: bool | None = None) -> None:
        active = (
            os.environ.get("AEGIS_PRODUCTION", "").strip().lower() in {"1", "true", "yes"}
            if production is None else production
        )
        if active:
            raise CoverageStorageError(
                "SQLite arsenal coverage backend is forbidden in production; use PostgreSQL"
            )
        self._connection = sqlite3.connect(str(path), check_same_thread=False)
        self._connection.executescript(SQLITE_SCHEMA)
        columns = {
            row[1] for row in self._connection.execute(
                "PRAGMA table_info(arsenal_coverage_records)"
            )
        }
        if "execution_metadata" not in columns:
            self._connection.execute(
                "ALTER TABLE arsenal_coverage_records "
                "ADD COLUMN execution_metadata TEXT NOT NULL DEFAULT '{}'"
            )
            self._connection.commit()
        self._lock = threading.Lock()

    def record(self, value: CapabilityCoverageRecord) -> tuple[CapabilityCoverageRecord, bool]:
        with self._lock, self._connection:
            row = self._connection.execute(
                f"SELECT {_COLUMNS} FROM arsenal_coverage_records WHERE idempotency_key=?",
                (value.idempotency_key,),
            ).fetchone()
            if row:
                if row[31] != _digest(value):
                    raise CoverageConflictError("coverage idempotency key has different content")
                return _record(row), False
            if value.supersedes_coverage_record_id:
                prior = self._connection.execute(
                    "SELECT capability_id FROM arsenal_coverage_records "
                    "WHERE coverage_record_id=?",
                    (value.supersedes_coverage_record_id,),
                ).fetchone()
                if not prior or prior[0] != value.capability_id:
                    raise CoverageConflictError(
                        "coverage correction must supersede an existing record for the same capability"
                    )
            try:
                self._connection.execute(
                    f"INSERT INTO arsenal_coverage_records ({_COLUMNS}) VALUES ("
                    + ",".join(["?"] * 32) + ")",
                    _values(value),
                )
            except sqlite3.IntegrityError as exc:
                raise CoverageConflictError("coverage record conflicts with immutable history") from exc
            return value, True

    def records(self) -> tuple[CapabilityCoverageRecord, ...]:
        rows = self._connection.execute(
            f"SELECT {_COLUMNS} FROM arsenal_coverage_records "
            "ORDER BY execution_timestamp,coverage_record_id"
        ).fetchall()
        return tuple(_record(row) for row in rows)

    def close(self) -> None:
        self._connection.close()


POSTGRES_SCHEMA = SQLITE_SCHEMA.replace(
    "executed INTEGER NOT NULL", "executed BOOLEAN NOT NULL"
).replace(
    "historical_evidence_invalid INTEGER NOT NULL",
    "historical_evidence_invalid BOOLEAN NOT NULL",
).replace(
    "CREATE TRIGGER IF NOT EXISTS arsenal_coverage_no_update\n"
    "BEFORE UPDATE ON arsenal_coverage_records BEGIN SELECT RAISE(ABORT,'immutable coverage'); END;\n"
    "CREATE TRIGGER IF NOT EXISTS arsenal_coverage_no_delete\n"
    "BEFORE DELETE ON arsenal_coverage_records BEGIN SELECT RAISE(ABORT,'immutable coverage'); END;\n",
    "",
) + """
ALTER TABLE arsenal_coverage_records
  ADD COLUMN IF NOT EXISTS execution_metadata TEXT NOT NULL DEFAULT '{}';
CREATE OR REPLACE FUNCTION arsenal_coverage_reject_mutation() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'immutable coverage'; END; $$ LANGUAGE plpgsql;
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgname = 'arsenal_coverage_immutable'
      AND tgrelid = 'arsenal_coverage_records'::regclass
  ) THEN
    CREATE TRIGGER arsenal_coverage_immutable
    BEFORE UPDATE OR DELETE ON arsenal_coverage_records
    FOR EACH ROW EXECUTE FUNCTION arsenal_coverage_reject_mutation();
  END IF;
END $$;
"""


class PostgresCoverageRepository:
    def __init__(self, dsn: str) -> None:
        if not dsn:
            raise CoverageStorageError("PostgreSQL arsenal coverage DSN is required")
        try:
            import psycopg
            from psycopg.rows import tuple_row
        except ImportError as exc:
            raise CoverageStorageError("PostgreSQL coverage dependencies are unavailable") from exc
        self._psycopg = psycopg
        self._connection = psycopg.connect(dsn, row_factory=tuple_row)
        with self._connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext('aegis_arsenal_coverage_schema'))"
            )
            # Recheck after acquiring the bootstrap lock. Running idempotent ALTER/CREATE
            # statements on every short-lived writer can deadlock with a concurrent INSERT:
            # PostgreSQL may retain a weaker DDL lock while waiting for AccessExclusiveLock.
            cursor.execute("""
                SELECT
                  to_regclass('public.arsenal_coverage_records') IS NOT NULL,
                  EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema='public'
                      AND table_name='arsenal_coverage_records'
                      AND column_name='execution_metadata'
                  ),
                  EXISTS (
                    SELECT 1 FROM pg_trigger
                    WHERE tgname='arsenal_coverage_immutable'
                      AND tgrelid=to_regclass('public.arsenal_coverage_records')
                  )
            """)
            table_exists, metadata_exists, trigger_exists = cursor.fetchone()
            if not (table_exists and metadata_exists and trigger_exists):
                cursor.execute(POSTGRES_SCHEMA)
        self._connection.commit()

    @contextmanager
    def _transaction(self):
        with self._connection.transaction(), self._connection.cursor() as cursor:
            yield cursor

    def record(self, value: CapabilityCoverageRecord) -> tuple[CapabilityCoverageRecord, bool]:
        with self._transaction() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (value.idempotency_key,))
            cursor.execute(
                f"SELECT {_COLUMNS} FROM arsenal_coverage_records WHERE idempotency_key=%s",
                (value.idempotency_key,),
            )
            row = cursor.fetchone()
            if row:
                if row[31] != _digest(value):
                    raise CoverageConflictError("coverage idempotency key has different content")
                return _record(row), False
            if value.supersedes_coverage_record_id:
                cursor.execute(
                    "SELECT capability_id FROM arsenal_coverage_records "
                    "WHERE coverage_record_id=%s",
                    (value.supersedes_coverage_record_id,),
                )
                prior = cursor.fetchone()
                if not prior or prior[0] != value.capability_id:
                    raise CoverageConflictError(
                        "coverage correction must supersede an existing record for the same capability"
                    )
            cursor.execute(
                f"INSERT INTO arsenal_coverage_records ({_COLUMNS}) VALUES ("
                + ",".join(["%s"] * 32) + ")",
                _values(value),
            )
            return value, True

    def records(self) -> tuple[CapabilityCoverageRecord, ...]:
        with self._connection.cursor() as cursor:
            cursor.execute(
                f"SELECT {_COLUMNS} FROM arsenal_coverage_records "
                "ORDER BY execution_timestamp,coverage_record_id"
            )
            return tuple(_record(row) for row in cursor.fetchall())

    def close(self) -> None:
        self._connection.close()


def repository_from_env() -> CoverageRepository:
    backend = os.environ.get("AEGIS_ARSENAL_COVERAGE_BACKEND", "postgresql").strip().lower()
    production = os.environ.get("AEGIS_PRODUCTION", "").strip().lower() in {"1", "true", "yes"}
    if backend == "sqlite":
        return SqliteCoverageRepository(
            os.environ.get("AEGIS_ARSENAL_COVERAGE_SQLITE", "arsenal-coverage.db"),
            production=production,
        )
    if backend != "postgresql":
        raise CoverageStorageError(f"unsupported arsenal coverage backend: {backend}")
    return PostgresCoverageRepository(os.environ.get("AEGIS_ARSENAL_COVERAGE_DB_URL", ""))


__all__ = [
    "CoverageConflictError", "CoverageRepository", "CoverageStorageError",
    "PostgresCoverageRepository", "SqliteCoverageRepository", "repository_from_env",
]
