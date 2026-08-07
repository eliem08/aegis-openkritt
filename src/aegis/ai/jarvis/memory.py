"""Durable program memory for the Jarvis agent operating system."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class MemoryRecord:
    program_id: str
    category: str
    key: str
    value: dict[str, Any]
    confidence: float


class AgentMemory:
    """Small SQLite-backed memory with deterministic program scoping."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._conn = sqlite3.connect(str(path))
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS memories (
                program_id TEXT NOT NULL,
                category TEXT NOT NULL,
                key TEXT NOT NULL,
                value_json TEXT NOT NULL,
                confidence REAL NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (program_id, category, key)
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS outcomes (
                program_id TEXT NOT NULL,
                weakness TEXT NOT NULL,
                accepted INTEGER NOT NULL,
                duplicate INTEGER NOT NULL,
                payout_usd REAL NOT NULL,
                cost_usd REAL NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def remember(self, record: MemoryRecord) -> None:
        if not 0 <= record.confidence <= 1:
            raise ValueError("confidence must be in [0, 1]")
        payload = json.dumps(record.value, sort_keys=True, separators=(",", ":"))
        self._conn.execute(
            """
            INSERT INTO memories(program_id, category, key, value_json, confidence)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(program_id, category, key)
            DO UPDATE SET
                value_json = excluded.value_json,
                confidence = excluded.confidence,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                record.program_id,
                record.category,
                record.key,
                payload,
                record.confidence,
            ),
        )
        self._conn.commit()

    def recall(
        self,
        program_id: str,
        *,
        category: str | None = None,
        minimum_confidence: float = 0.0,
        limit: int = 100,
    ) -> tuple[MemoryRecord, ...]:
        query = (
            "SELECT program_id, category, key, value_json, confidence "
            "FROM memories WHERE program_id = ? AND confidence >= ?"
        )
        params: list[Any] = [program_id, minimum_confidence]
        if category is not None:
            query += " AND category = ?"
            params.append(category)
        query += " ORDER BY confidence DESC, updated_at DESC LIMIT ?"
        params.append(max(1, min(limit, 1000)))

        rows = self._conn.execute(query, params).fetchall()
        return tuple(
            MemoryRecord(
                program_id=row[0],
                category=row[1],
                key=row[2],
                value=json.loads(row[3]),
                confidence=float(row[4]),
            )
            for row in rows
        )

    def record_outcome(
        self,
        *,
        program_id: str,
        weakness: str,
        accepted: bool,
        duplicate: bool,
        payout_usd: float,
        cost_usd: float,
    ) -> None:
        if payout_usd < 0 or cost_usd < 0:
            raise ValueError("payout and cost must be non-negative")
        self._conn.execute(
            """
            INSERT INTO outcomes(
                program_id, weakness, accepted, duplicate, payout_usd, cost_usd
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                program_id,
                weakness.lower().strip(),
                int(accepted),
                int(duplicate),
                payout_usd,
                cost_usd,
            ),
        )
        self._conn.commit()

    def outcome_stats(self, program_id: str, weakness: str) -> dict[str, float]:
        row = self._conn.execute(
            """
            SELECT
                COUNT(*),
                COALESCE(SUM(accepted), 0),
                COALESCE(SUM(duplicate), 0),
                COALESCE(SUM(payout_usd), 0),
                COALESCE(SUM(cost_usd), 0)
            FROM outcomes
            WHERE program_id = ? AND weakness = ?
            """,
            (program_id, weakness.lower().strip()),
        ).fetchone()
        total = int(row[0]) if row else 0
        accepted = int(row[1]) if row else 0
        duplicates = int(row[2]) if row else 0
        return {
            "samples": float(total),
            "acceptance_rate": accepted / total if total else 0.5,
            "duplicate_rate": duplicates / total if total else 0.25,
            "gross_payout_usd": float(row[3]) if row else 0.0,
            "cost_usd": float(row[4]) if row else 0.0,
        }
