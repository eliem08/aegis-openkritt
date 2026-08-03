"""HackerOne report outcomes -> learning verdicts.

A submitted report is linked to the finding it came from; the program's resolution
is then folded into the loop (resolved -> confirmed, duplicate -> duplicate,
not-applicable -> false-positive), idempotently and only for reports we originated.
"""

from __future__ import annotations

from aegis.learn import (
    Calibration,
    OutcomeStore,
    SubmissionLedger,
    Verdict,
    map_report_state,
    sync_submission_outcomes,
)


def _report(rid, state):
    return {"id": rid, "type": "report", "attributes": {"state": state, "title": f"r{rid}"}}


# --- state mapping ----------------------------------------------------------

def test_state_maps_to_verdicts():
    assert map_report_state("resolved") is Verdict.CONFIRMED
    assert map_report_state("duplicate") is Verdict.DUPLICATE
    assert map_report_state("not-applicable") is Verdict.FALSE_POSITIVE
    assert map_report_state("spam") is Verdict.FALSE_POSITIVE
    # non-decisive states are left pending (None)
    assert map_report_state("triaged") is None
    assert map_report_state("informative") is None
    assert map_report_state("new") is None


# --- sync -------------------------------------------------------------------

def test_sync_attributes_outcomes_to_the_originating_detector():
    ledger = SubmissionLedger()
    outcomes = OutcomeStore()
    ledger.record_link("101", detector="analyzer:contract", cwe="CWE-841", asset="V.sol")
    ledger.record_link("102", detector="analyzer:hardening", cwe="CWE-79")

    res = sync_submission_outcomes([_report("101", "resolved"), _report("102", "not-applicable")],
                                   ledger, outcomes)
    assert res.recorded == 2 and res.by_verdict == {"confirmed": 1, "false_positive": 1}

    cal = Calibration.from_outcomes(outcomes.all())
    assert cal.prior(detector="analyzer:contract") > 0.5     # resolved -> reliable
    assert cal.prior(detector="analyzer:hardening") < 0.5     # N/A -> unreliable


def test_sync_skips_unlinked_and_pending_reports():
    ledger = SubmissionLedger()
    outcomes = OutcomeStore()
    ledger.record_link("200", detector="d", cwe="CWE-1")
    res = sync_submission_outcomes([
        _report("200", "triaged"),      # linked but not decisive -> pending
        _report("999", "resolved"),     # decisive but not ours -> unlinked
    ], ledger, outcomes)
    assert res.recorded == 0 and res.skipped_pending == 1 and res.skipped_unlinked == 1
    assert outcomes.count() == 0


def test_sync_is_idempotent_per_report():
    ledger = SubmissionLedger()
    outcomes = OutcomeStore()
    ledger.record_link("300", detector="d", cwe="CWE-1")
    reports = [_report("300", "resolved")]

    first = sync_submission_outcomes(reports, ledger, outcomes)
    second = sync_submission_outcomes(reports, ledger, outcomes)     # re-sync
    assert first.recorded == 1 and second.recorded == 0 and second.already_recorded == 1
    assert outcomes.count() == 1                                     # not double-counted


def test_report_that_becomes_decisive_later_is_recorded_once():
    ledger = SubmissionLedger()
    outcomes = OutcomeStore()
    ledger.record_link("400", detector="d", cwe="CWE-1")

    pending = sync_submission_outcomes([_report("400", "triaged")], ledger, outcomes)
    assert pending.recorded == 0 and outcomes.count() == 0
    resolved = sync_submission_outcomes([_report("400", "resolved")], ledger, outcomes)
    assert resolved.recorded == 1 and outcomes.count() == 1
