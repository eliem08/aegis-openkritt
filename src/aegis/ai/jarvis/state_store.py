"""Durable learning and mission state for the advanced Jarvis council."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class LearnedPrior:
    program_id: str
    weakness: str
    samples: int
    acceptance_probability: float
    uniqueness_probability: float
    mean_payout_usd: float | None
    mean_cost_usd: float


@dataclass(frozen=True)
class VulnerabilityFamily:
    family_id: str
    mechanism: str
    invariant: str
    cwe: str = ""
    exemplars: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    confidence: float = 0.5


@dataclass(frozen=True)
class RuleCandidateRecord:
    rule_id: str
    engine: str
    family_id: str
    rule_text: str
    positive_fixtures: int = 0
    negative_fixtures: int = 0
    precision: float = 0.0
    recall: float = 0.0
    status: str = "draft"


@dataclass(frozen=True)
class CoverageObservation:
    program_id: str
    surface: str
    weakness: str
    attempts: int = 0
    successful_findings: int = 0
    expected_value_usd: float = 0.0
    changed_since_last_attempt: bool = False
    last_result: str = ""


@dataclass(frozen=True)
class MissionSnapshot:
    mission_id: str
    scope_digest: str
    objective: str
    state: str
    payload: dict[str, Any]
    cursor: int = 0


class JarvisStateStore:
    """SQLite-backed source of truth for learning, memory, and mission resume."""

    SCHEMA_VERSION = 1

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA busy_timeout = 5000")
        if self.path != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def _create_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS schema_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS learned_priors (
                program_id TEXT NOT NULL,
                weakness TEXT NOT NULL,
                alpha_accept REAL NOT NULL DEFAULT 1,
                beta_accept REAL NOT NULL DEFAULT 1,
                alpha_unique REAL NOT NULL DEFAULT 1,
                beta_unique REAL NOT NULL DEFAULT 1,
                payout_sum REAL NOT NULL DEFAULT 0,
                payout_count INTEGER NOT NULL DEFAULT 0,
                cost_sum REAL NOT NULL DEFAULT 0,
                samples INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (program_id, weakness)
            );

            CREATE TABLE IF NOT EXISTS vulnerability_families (
                family_id TEXT PRIMARY KEY,
                mechanism TEXT NOT NULL,
                invariant TEXT NOT NULL,
                cwe TEXT NOT NULL,
                exemplars_json TEXT NOT NULL,
                tags_json TEXT NOT NULL,
                confidence REAL NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS rule_candidates (
                rule_id TEXT PRIMARY KEY,
                engine TEXT NOT NULL,
                family_id TEXT NOT NULL,
                rule_text TEXT NOT NULL,
                positive_fixtures INTEGER NOT NULL,
                negative_fixtures INTEGER NOT NULL,
                precision REAL NOT NULL,
                recall REAL NOT NULL,
                status TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS coverage_observations (
                program_id TEXT NOT NULL,
                surface TEXT NOT NULL,
                weakness TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                successful_findings INTEGER NOT NULL,
                expected_value_usd REAL NOT NULL,
                changed_since_last_attempt INTEGER NOT NULL,
                last_result TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (program_id, surface, weakness)
            );

            CREATE TABLE IF NOT EXISTS mission_snapshots (
                mission_id TEXT PRIMARY KEY,
                scope_digest TEXT NOT NULL,
                objective TEXT NOT NULL,
                state TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                cursor INTEGER NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        self._conn.execute(
            "INSERT OR REPLACE INTO schema_meta(key, value) VALUES ('schema_version', ?)",
            (str(self.SCHEMA_VERSION),),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> JarvisStateStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @staticmethod
    def _norm(value: str) -> str:
        return value.strip().lower()

    def record_outcome(
        self,
        *,
        program_id: str,
        weakness: str,
        accepted: bool,
        duplicate: bool,
        payout_usd: float | None,
        cost_usd: float,
    ) -> LearnedPrior:
        if (payout_usd is not None and payout_usd < 0) or cost_usd < 0:
            raise ValueError("payout and cost must be non-negative")
        program = self._norm(program_id)
        weakness_key = self._norm(weakness)
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO learned_priors(program_id, weakness)
                VALUES (?, ?)
                ON CONFLICT(program_id, weakness) DO NOTHING
                """,
                (program, weakness_key),
            )
            self._conn.execute(
                """
                UPDATE learned_priors SET
                    alpha_accept = alpha_accept + ?,
                    beta_accept = beta_accept + ?,
                    alpha_unique = alpha_unique + ?,
                    beta_unique = beta_unique + ?,
                    payout_sum = payout_sum + ?,
                    payout_count = payout_count + ?,
                    cost_sum = cost_sum + ?,
                    samples = samples + 1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE program_id = ? AND weakness = ?
                """,
                (
                    1 if accepted else 0,
                    0 if accepted else 1,
                    0 if duplicate else 1,
                    1 if duplicate else 0,
                    payout_usd or 0.0,
                    1 if payout_usd is not None and payout_usd > 0 else 0,
                    cost_usd,
                    program,
                    weakness_key,
                ),
            )
        return self.learned_prior(program, weakness_key)

    def learned_prior(self, program_id: str, weakness: str) -> LearnedPrior:
        program = self._norm(program_id)
        weakness_key = self._norm(weakness)
        row = self._conn.execute(
            "SELECT * FROM learned_priors WHERE program_id = ? AND weakness = ?",
            (program, weakness_key),
        ).fetchone()
        if row is None:
            return LearnedPrior(program, weakness_key, 0, 0.5, 0.5, None, 0.0)
        return LearnedPrior(
            program_id=program,
            weakness=weakness_key,
            samples=int(row["samples"]),
            acceptance_probability=float(row["alpha_accept"])
            / (float(row["alpha_accept"]) + float(row["beta_accept"])),
            uniqueness_probability=float(row["alpha_unique"])
            / (float(row["alpha_unique"]) + float(row["beta_unique"])),
            mean_payout_usd=(
                float(row["payout_sum"]) / int(row["payout_count"])
                if int(row["payout_count"]) > 0
                else None
            ),
            mean_cost_usd=float(row["cost_sum"]) / max(1, int(row["samples"])),
        )

    def upsert_family(self, family: VulnerabilityFamily) -> None:
        if not 0.0 <= family.confidence <= 1.0:
            raise ValueError("confidence must be in [0, 1]")
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO vulnerability_families(
                    family_id, mechanism, invariant, cwe, exemplars_json, tags_json, confidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(family_id) DO UPDATE SET
                    mechanism = excluded.mechanism,
                    invariant = excluded.invariant,
                    cwe = excluded.cwe,
                    exemplars_json = excluded.exemplars_json,
                    tags_json = excluded.tags_json,
                    confidence = excluded.confidence,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    family.family_id,
                    family.mechanism,
                    family.invariant,
                    family.cwe,
                    json.dumps(sorted(set(family.exemplars))),
                    json.dumps(sorted(set(family.tags))),
                    family.confidence,
                ),
            )

    def families(self, *, minimum_confidence: float = 0.0) -> tuple[VulnerabilityFamily, ...]:
        rows = self._conn.execute(
            """
            SELECT * FROM vulnerability_families
            WHERE confidence >= ?
            ORDER BY confidence DESC, family_id
            """,
            (minimum_confidence,),
        ).fetchall()
        return tuple(
            VulnerabilityFamily(
                family_id=row["family_id"],
                mechanism=row["mechanism"],
                invariant=row["invariant"],
                cwe=row["cwe"],
                exemplars=tuple(json.loads(row["exemplars_json"])),
                tags=tuple(json.loads(row["tags_json"])),
                confidence=float(row["confidence"]),
            )
            for row in rows
        )

    def upsert_rule_candidate(self, record: RuleCandidateRecord) -> None:
        if record.engine not in {"semgrep", "codeql"}:
            raise ValueError("unsupported rule engine")
        if not 0.0 <= record.precision <= 1.0 or not 0.0 <= record.recall <= 1.0:
            raise ValueError("precision and recall must be in [0, 1]")
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO rule_candidates(
                    rule_id, engine, family_id, rule_text, positive_fixtures,
                    negative_fixtures, precision, recall, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(rule_id) DO UPDATE SET
                    rule_text = excluded.rule_text,
                    positive_fixtures = excluded.positive_fixtures,
                    negative_fixtures = excluded.negative_fixtures,
                    precision = excluded.precision,
                    recall = excluded.recall,
                    status = excluded.status,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    record.rule_id,
                    record.engine,
                    record.family_id,
                    record.rule_text,
                    record.positive_fixtures,
                    record.negative_fixtures,
                    record.precision,
                    record.recall,
                    record.status,
                ),
            )

    def rule_candidate(self, rule_id: str) -> RuleCandidateRecord | None:
        row = self._conn.execute(
            "SELECT * FROM rule_candidates WHERE rule_id = ?",
            (rule_id,),
        ).fetchone()
        if row is None:
            return None
        return RuleCandidateRecord(
            rule_id=row["rule_id"],
            engine=row["engine"],
            family_id=row["family_id"],
            rule_text=row["rule_text"],
            positive_fixtures=int(row["positive_fixtures"]),
            negative_fixtures=int(row["negative_fixtures"]),
            precision=float(row["precision"]),
            recall=float(row["recall"]),
            status=row["status"],
        )

    def upsert_coverage(self, observation: CoverageObservation) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO coverage_observations(
                    program_id, surface, weakness, attempts, successful_findings,
                    expected_value_usd, changed_since_last_attempt, last_result
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(program_id, surface, weakness) DO UPDATE SET
                    attempts = excluded.attempts,
                    successful_findings = excluded.successful_findings,
                    expected_value_usd = excluded.expected_value_usd,
                    changed_since_last_attempt = excluded.changed_since_last_attempt,
                    last_result = excluded.last_result,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    self._norm(observation.program_id),
                    observation.surface,
                    self._norm(observation.weakness),
                    max(0, observation.attempts),
                    max(0, observation.successful_findings),
                    max(0.0, observation.expected_value_usd),
                    int(observation.changed_since_last_attempt),
                    observation.last_result,
                ),
            )

    def coverage(self, program_id: str) -> tuple[CoverageObservation, ...]:
        rows = self._conn.execute(
            """
            SELECT * FROM coverage_observations
            WHERE program_id = ?
            ORDER BY surface, weakness
            """,
            (self._norm(program_id),),
        ).fetchall()
        return tuple(
            CoverageObservation(
                program_id=row["program_id"],
                surface=row["surface"],
                weakness=row["weakness"],
                attempts=int(row["attempts"]),
                successful_findings=int(row["successful_findings"]),
                expected_value_usd=float(row["expected_value_usd"]),
                changed_since_last_attempt=bool(row["changed_since_last_attempt"]),
                last_result=row["last_result"],
            )
            for row in rows
        )

    def save_mission(self, snapshot: MissionSnapshot) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO mission_snapshots(
                    mission_id, scope_digest, objective, state, payload_json, cursor
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(mission_id) DO UPDATE SET
                    scope_digest = excluded.scope_digest,
                    objective = excluded.objective,
                    state = excluded.state,
                    payload_json = excluded.payload_json,
                    cursor = excluded.cursor,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    snapshot.mission_id,
                    snapshot.scope_digest,
                    snapshot.objective,
                    snapshot.state,
                    json.dumps(snapshot.payload, sort_keys=True, separators=(",", ":")),
                    max(0, snapshot.cursor),
                ),
            )

    def load_mission(self, mission_id: str) -> MissionSnapshot | None:
        row = self._conn.execute(
            "SELECT * FROM mission_snapshots WHERE mission_id = ?",
            (mission_id,),
        ).fetchone()
        if row is None:
            return None
        return MissionSnapshot(
            mission_id=row["mission_id"],
            scope_digest=row["scope_digest"],
            objective=row["objective"],
            state=row["state"],
            payload=json.loads(row["payload_json"]),
            cursor=int(row["cursor"]),
        )

    def list_missions(self, states: Iterable[str] = ()) -> tuple[MissionSnapshot, ...]:
        state_list = tuple(states)
        query = "SELECT mission_id FROM mission_snapshots"
        params: tuple[str, ...] = ()
        if state_list:
            placeholders = ",".join("?" for _ in state_list)
            query += f" WHERE state IN ({placeholders})"
            params = state_list
        query += " ORDER BY updated_at, mission_id"
        rows = self._conn.execute(query, params).fetchall()
        return tuple(
            snapshot
            for row in rows
            if (snapshot := self.load_mission(row["mission_id"])) is not None
        )
