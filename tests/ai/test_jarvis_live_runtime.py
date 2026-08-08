from __future__ import annotations

from aegis.ai.agentic_os import EvidenceStage
from aegis.ai.jarvis_runtime import (
    annotate_reproduction,
    annotate_source_validation,
    estimate_finding_economics,
    evaluate_tier3_source_review,
    prioritize_council,
)


def _row(*, severity="high", confidence=0.9):
    return {
        "json_answer": {
            "vulnerability_type": "CWE-862",
            "severity": severity,
            "file_path": "app/routes.py",
            "line": 42,
            "summary": "missing ownership check",
        },
        "validation": {
            "verdict": "confirmed",
            "reason": "pinned source shows the object is loaded without an ownership predicate",
            "confidence": confidence,
            "anchors": ["app/routes.py:42"],
        },
        "agreement": 3,
        "samples": 3,
    }


def test_source_validation_enters_canonical_lifecycle():
    row = _row()
    state = annotate_source_validation(row, scope_digest="scope:abc")
    assert state["stage"] == EvidenceStage.SOURCE_SUPPORTED.value
    assert state["policy"]["approved"] is True
    assert state["proposal"]["role"] == "evidence"
    assert state["evidence"]


def test_unresolved_stays_candidate():
    row = _row()
    row["validation"]["verdict"] = "unresolved"
    state = annotate_source_validation(row)
    assert state["stage"] == EvidenceStage.CANDIDATE.value


def test_economics_is_net_value_not_severity_only(monkeypatch):
    monkeypatch.setenv("AEGIS_JARVIS_DUPLICATE_PRIOR", "0.10")
    monkeypatch.setenv("AEGIS_JARVIS_MIN_FINDING_NET_EV", "1")
    high = estimate_finding_economics(_row(severity="high", confidence=0.95))
    weak = estimate_finding_economics(_row(severity="low", confidence=0.05))
    assert high.expected_net_usd > weak.expected_net_usd
    assert high.priority == "promote"


def test_council_portfolio_is_bounded(monkeypatch):
    monkeypatch.setenv("AEGIS_JARVIS_COUNCIL_MAX_FINDINGS", "2")
    rows = [_row(), _row(), _row()]
    for index, row in enumerate(rows):
        row["json_answer"]["line"] += index
        annotate_source_validation(row)
    promoted, deferred = prioritize_council(rows)
    assert len(promoted) == 2
    assert len(deferred) == 1
    assert deferred[0]["jarvis"]["economics"]["priority"] == "retain_cheap"


def test_reproduction_advances_only_on_real_local_oracle():
    row = _row()
    annotate_source_validation(row)
    row["reproduction"] = {"verdict": "not_reproduced", "summary": "oracle did not fire"}
    annotate_reproduction(row)
    assert row["jarvis"]["stage"] == EvidenceStage.SOURCE_SUPPORTED.value

    row["reproduction"] = {"verdict": "reproduced", "summary": "nonce oracle observed"}
    annotate_reproduction(row)
    assert row["jarvis"]["stage"] == EvidenceStage.LOCALLY_REPRODUCED.value


def test_every_registered_active_capability_is_vetoed_in_source_review():
    evaluated = evaluate_tier3_source_review()
    assert len(evaluated) >= 6
    assert all(proposal.requires_network for proposal, _ in evaluated)
    assert all(not decision.approved for _, decision in evaluated)
    assert all("network" in decision.reason for _, decision in evaluated)
