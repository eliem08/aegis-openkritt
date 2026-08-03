"""Close the loop with real HackerOne outcomes.

Human verdicts teach the loop from review; this teaches it from *reality* — how the
program actually resolved a submitted report. Two steps:

1. **Link** a submitted report back to the finding that produced it
   (:class:`SubmissionLedger`), so an outcome can be attributed to the right
   detector/CWE.
2. **Sync** report states into verdicts (:func:`sync_submission_outcomes`):
   ``resolved`` → confirmed, ``duplicate`` → duplicate, ``not-applicable`` / ``spam``
   → false-positive. Non-decisive states (triaged, informative, needs-more-info, …)
   are left pending. Recording is idempotent per report, so re-syncing is safe.

This never submits or changes anything on HackerOne — it only *reads* the states of
reports you already submitted and feeds them into calibration + memory.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass, field

from .store import Outcome, OutcomeStore, Verdict

# HackerOne report state -> learning verdict. Only decisive states map; the rest
# (new, triaged, needs-more-info, informative, retesting) stay pending.
_STATE_VERDICT = {
    "resolved": Verdict.CONFIRMED,
    "duplicate": Verdict.DUPLICATE,
    "not-applicable": Verdict.FALSE_POSITIVE,
    "spam": Verdict.FALSE_POSITIVE,
}


def map_report_state(state) -> Verdict | None:
    return _STATE_VERDICT.get(str(state or "").strip().lower().replace("_", "-"))


@dataclass
class SyncResult:
    recorded: int = 0
    by_verdict: dict = field(default_factory=dict)
    skipped_pending: int = 0
    skipped_unlinked: int = 0
    already_recorded: int = 0


class SubmissionLedger:
    """Links a HackerOne report id to the finding (detector/CWE) it came from, and
    remembers which reports have already been folded into the learning loop."""

    def __init__(self, path: str | None = None):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path or ":memory:", check_same_thread=False)
        self._conn.executescript(
            "CREATE TABLE IF NOT EXISTS submissions ("
            " report_id TEXT PRIMARY KEY, detector TEXT, cwe TEXT, fingerprint TEXT,"
            " asset TEXT, program TEXT, summary TEXT);"
            "CREATE TABLE IF NOT EXISTS recorded ("
            " report_id TEXT PRIMARY KEY, state TEXT, verdict TEXT);")
        self._conn.commit()

    def record_link(self, report_id: str, *, detector: str = "", cwe: str = "",
                    fingerprint: str = "", asset: str = "", program: str = "",
                    summary: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO submissions VALUES (?,?,?,?,?,?,?)",
                (str(report_id), detector, cwe, fingerprint, asset, program, summary[:240]))
            self._conn.commit()

    def get_link(self, report_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT detector, cwe, fingerprint, asset, program, summary "
                "FROM submissions WHERE report_id=?", (str(report_id),)).fetchone()
        if not row:
            return None
        return dict(detector=row[0], cwe=row[1], fingerprint=row[2], asset=row[3],
                    program=row[4], summary=row[5])

    def is_recorded(self, report_id: str) -> bool:
        with self._lock:
            return self._conn.execute(
                "SELECT 1 FROM recorded WHERE report_id=?", (str(report_id),)).fetchone() is not None

    def mark_recorded(self, report_id: str, state: str, verdict: Verdict) -> None:
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO recorded VALUES (?,?,?)",
                               (str(report_id), state, Verdict(verdict).value))
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def sync_submission_outcomes(reports, ledger: SubmissionLedger,
                             outcomes: OutcomeStore) -> SyncResult:
    """Fold decisive HackerOne report states into the outcome store (idempotent)."""
    result = SyncResult()
    for report in reports or []:
        report_id = str(report.get("id") or "")
        state = (report.get("attributes") or {}).get("state") if isinstance(report, dict) else None
        verdict = map_report_state(state)
        if verdict is None:
            result.skipped_pending += 1
            continue
        link = ledger.get_link(report_id)
        if link is None:
            result.skipped_unlinked += 1        # not a report we originated / tracked
            continue
        if ledger.is_recorded(report_id):
            result.already_recorded += 1        # decisive outcome already folded in
            continue
        outcomes.record(Outcome(
            detector=link["detector"], cwe=link["cwe"], verdict=verdict,
            fingerprint=link["fingerprint"], asset=link["asset"], program=link["program"],
            summary=link["summary"] or f"HackerOne report {report_id} -> {state}"))
        ledger.mark_recorded(report_id, str(state), verdict)
        result.recorded += 1
        result.by_verdict[verdict.value] = result.by_verdict.get(verdict.value, 0) + 1
    return result


def sync_hackerone_outcomes(h1_client, ledger: SubmissionLedger,
                            outcomes: OutcomeStore) -> SyncResult:
    """Fetch the authenticated hacker's reports and sync their states into the loop."""
    return sync_submission_outcomes(h1_client.list_my_reports(), ledger, outcomes)
