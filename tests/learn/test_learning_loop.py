"""The learning loop: verdicts -> calibration priors + retrieval memory.

Feedback recorded in the outcome store auto-reweights the console ranking and feeds
the LLM planner few-shot context — no retraining. Deterministic throughout.
"""

from __future__ import annotations

from aegis.learn import (
    Calibration,
    Outcome,
    OutcomeStore,
    PlannerKnowledge,
    Verdict,
    learned_context,
    recall,
)
from aegis.model import Candidate
from aegis.report import build_console


def _store(*outcomes) -> OutcomeStore:
    s = OutcomeStore()
    for o in outcomes:
        s.record(o)
    return s


# --- store ------------------------------------------------------------------

def test_store_round_trips_outcomes():
    s = _store(Outcome(detector="analyzer:contract", cwe="CWE-841", verdict=Verdict.CONFIRMED))
    assert s.count() == 1
    got = s.all()[0]
    assert got.cwe == "CWE-841" and got.verdict is Verdict.CONFIRMED


# --- calibration ------------------------------------------------------------

def test_precision_rises_and_falls_with_verdicts():
    reliable = _store(*[Outcome(detector="good", cwe="CWE-1", verdict=Verdict.CONFIRMED)] * 5)
    noisy = _store(*[Outcome(detector="bad", cwe="CWE-2", verdict=Verdict.FALSE_POSITIVE)] * 5)
    good = Calibration.from_outcomes(reliable.all()).prior(detector="good")
    bad = Calibration.from_outcomes(noisy.all()).prior(detector="bad")
    assert good > 0.7 and bad < 0.3                       # learned from the verdicts


def test_duplicate_counts_as_a_true_detection():
    s = _store(Outcome(detector="d", cwe="CWE-1", verdict=Verdict.DUPLICATE))
    assert Calibration.from_outcomes(s.all()).prior(detector="d") > 0.5


def test_no_evidence_is_neutral():
    cal = Calibration.from_outcomes([])
    assert cal.prior(detector="anything") == 0.5
    c = Candidate(asset="x", worker="w", cwe="CWE-9")
    assert cal.factor(c) == 1.0                           # neutral multiplier


# --- calibration reranks the console ----------------------------------------

def test_console_reranks_after_feedback():
    noisy = Candidate(asset="a.test", route="/x", worker="analyzer:noisy", cwe="CWE-100",
                      confidence=0.9, p_exploit=0.9, business_impact=0.9)
    solid = Candidate(asset="b.test", route="/y", worker="analyzer:solid", cwe="CWE-200",
                      confidence=0.6, p_exploit=0.6, business_impact=0.6)

    # Before any feedback, the higher raw score ranks first.
    plain = build_console([noisy, solid])
    assert plain["items"][0]["worker"] == "analyzer:noisy"

    # Teach the loop: the noisy detector is usually wrong, the solid one usually right.
    store = _store(
        *[Outcome(detector="analyzer:noisy", cwe="CWE-100", verdict=Verdict.FALSE_POSITIVE)] * 6,
        *[Outcome(detector="analyzer:solid", cwe="CWE-200", verdict=Verdict.CONFIRMED)] * 6)
    cal = Calibration.from_outcomes(store.all())
    learned = build_console([noisy, solid], calibration=cal)
    assert learned["items"][0]["worker"] == "analyzer:solid"   # order flipped from feedback
    assert learned["items"][0]["learned_prior"] > 0.7


# --- retrieval memory for the planner ---------------------------------------

def test_recall_prefers_relevant_and_recent():
    store = _store(
        Outcome(detector="d", cwe="CWE-841", verdict=Verdict.CONFIRMED, summary="reentrancy in withdraw"),
        Outcome(detector="d", cwe="CWE-79", verdict=Verdict.FALSE_POSITIVE, summary="reflected xss noise"))
    hits = recall(store.all(), cwe="CWE-841", k=1)
    assert hits and hits[0]["summary"] == "reentrancy in withdraw"


def test_learned_context_splits_confirmed_and_false_positives():
    store = _store(
        Outcome(detector="d", cwe="CWE-841", verdict=Verdict.CONFIRMED, summary="real drain"),
        Outcome(detector="d", cwe="CWE-841", verdict=Verdict.FALSE_POSITIVE, summary="guarded, safe"))
    ctx = learned_context(store.all(), cwe="CWE-841")
    assert "real drain" in ctx["confirmed_examples"]
    assert "guarded, safe" in ctx["false_positive_examples"]


def test_planner_knowledge_is_empty_until_there_is_feedback():
    empty = PlannerKnowledge(OutcomeStore())
    assert empty.context(None, None) == {}
    store = _store(Outcome(detector="d", cwe="CWE-1", verdict=Verdict.CONFIRMED, summary="s"))
    assert PlannerKnowledge(store).context(None, None)["prior_precision"] >= 0.5
