"""Outcome store — the memory the learning loop is built on.

Every time a human (or, later, a HackerOne submission result) judges a finding,
that judgement is recorded here as an :class:`Outcome`. The store is the single
source the calibration priors and the retrieval memory both read from, so the
system improves automatically as verdicts accumulate — no retraining, no manual
tuning. It is deliberately small and dependency-free (sqlite), and defaults to
in-memory so tests and dev runs never leave state behind.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class Verdict(str, Enum):
    CONFIRMED = "confirmed"          # a real, novel issue (true positive)
    DUPLICATE = "duplicate"          # a real issue, already known (still a true detection)
    FALSE_POSITIVE = "false_positive"  # not an issue (the detector was wrong)
    PENDING = "pending"              # awaiting judgement

    @property
    def is_true_detection(self) -> bool:
        return self in (Verdict.CONFIRMED, Verdict.DUPLICATE)

    @property
    def is_false(self) -> bool:
        return self is Verdict.FALSE_POSITIVE


@dataclass(frozen=True)
class Outcome:
    detector: str = ""               # the worker/source that produced the finding
    cwe: str = ""
    verdict: Verdict = Verdict.PENDING
    fingerprint: str = ""
    asset: str = ""
    program: str = ""
    summary: str = ""                # short, redacted description (no payloads)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


class OutcomeStore:
    def __init__(self, path: str | None = None):
        # A single shared connection guarded by a lock (FastAPI serves on threads).
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path or ":memory:", check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS outcomes ("
            "detector TEXT, cwe TEXT, verdict TEXT, fingerprint TEXT, asset TEXT, "
            "program TEXT, summary TEXT, created_at TEXT)")
        self._conn.commit()

    def record(self, outcome: Outcome) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO outcomes VALUES (?,?,?,?,?,?,?,?)",
                (outcome.detector, outcome.cwe, Verdict(outcome.verdict).value,
                 outcome.fingerprint, outcome.asset, outcome.program, outcome.summary,
                 outcome.created_at))
            self._conn.commit()

    def all(self) -> list[Outcome]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT detector, cwe, verdict, fingerprint, asset, program, summary, "
                "created_at FROM outcomes ORDER BY created_at").fetchall()
        return [Outcome(detector=r[0], cwe=r[1], verdict=Verdict(r[2]), fingerprint=r[3],
                        asset=r[4], program=r[5], summary=r[6], created_at=r[7]) for r in rows]

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM outcomes").fetchone()[0]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
