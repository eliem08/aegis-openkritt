from __future__ import annotations

import json

from aegis.ai.jarvis.state_store import JarvisStateStore
from aegis.ai.jarvis_graph import load_graph
from aegis.ai.jarvis_persistence import (
    checkpoint_phase,
    load_finding,
    mission_state,
    persist_finding,
)
from aegis.ai.jarvis_runtime import estimate_finding_economics


def _row():
    return {
        "json_answer": {
            "vulnerability_type": "CWE-862",
            "severity": "high",
            "file_path": "routes.py",
            "line": 12,
            "summary": "missing ownership check",
        },
        "validation": {"verdict": "confirmed", "confidence": 0.9},
        "jarvis": {
            "finding_id": "finding:test",
            "stage": "source_supported",
            "program_id": "acme",
            "source_platform": "hackerone",
            "repository": "acme/app",
            "scope_digest": "scope:1",
            "evidence": ["ev1:source-validation:test"],
        },
        "agreement": 3,
        "samples": 3,
    }


def test_finding_state_persists_without_raw_source(tmp_path):
    db = tmp_path / "jarvis.db"
    row = _row()
    persist_finding(row, repository="acme/app", scope_digest="scope:1", path=db)
    saved = load_finding("finding:test", path=db)
    assert saved is not None
    assert saved["repository"] == "acme/app"
    assert saved["jarvis"]["stage"] == "source_supported"
    assert "source" not in saved

    graph = load_graph("acme/app", path=db)
    assert "repository:acme/app" in graph.nodes
    assert "program:acme" in graph.nodes
    assert "finding:test" in graph.nodes
    assert graph.neighbors("program:acme", "authorizes") == ("repository:acme/app",)
    assert "ev1:source-validation:test" in graph.neighbors("finding:test", "supported_by")


def test_live_mission_checkpoints_are_monotonic(tmp_path):
    db = tmp_path / "jarvis.db"
    checkpoint_phase("acme/app", "validate", scope_digest="scope:1", path=db)
    state = mission_state("acme/app", path=db)
    assert state is not None
    completed = {t["task_id"] for t in state["tasks"] if t["state"] == "complete"}
    assert {"authorize", "scan", "analyze", "validate"} <= completed
    assert "reproduce" not in completed

    checkpoint_phase("acme/app", "skeptic", scope_digest="scope:1", path=db)
    state = mission_state("acme/app", path=db)
    completed = {t["task_id"] for t in state["tasks"] if t["state"] == "complete"}
    assert {"economics", "skeptic"} <= completed


def test_real_outcomes_shift_finding_ev_without_overfitting(tmp_path, monkeypatch):
    db = tmp_path / "jarvis.db"
    monkeypatch.setenv("AEGIS_JARVIS_DB", str(db))
    row = _row()

    neutral = estimate_finding_economics(row, handle="acme")

    with JarvisStateStore(db) as store:
        for _ in range(20):
            store.record_outcome(
                program_id="acme",
                weakness="CWE-862",
                accepted=True,
                duplicate=False,
                payout_usd=3000,
                cost_usd=10,
            )

    learned = estimate_finding_economics(row, handle="acme")
    assert learned.prior_samples == 20
    assert learned.acceptance_probability > neutral.acceptance_probability
    assert learned.uniqueness_probability > neutral.uniqueness_probability
    assert learned.expected_gross_usd > neutral.expected_gross_usd


def test_disclosure_corpus_is_only_a_bounded_pseudoprior(tmp_path, monkeypatch):
    db = tmp_path / "jarvis.db"
    corpus = tmp_path / "reports.jsonl"
    monkeypatch.setenv("AEGIS_JARVIS_DB", str(db))
    with JarvisStateStore(db):
        pass

    row = _row()
    baseline = estimate_finding_economics(row, handle="acme")

    records = [
        {"report_id": f"r{i}", "program": "acme", "cwe": "CWE-862",
         "severity": "high", "bounty": 1500 + i * 100}
        for i in range(4)
    ]
    records.append({"report_id": "other", "program": "acme", "cwe": "CWE-79",
                    "severity": "medium", "bounty": 300})
    corpus.write_text("\n".join(json.dumps(item) for item in records) + "\n", encoding="utf-8")
    monkeypatch.setenv("AEGIS_KNOWLEDGE_CORPUS", str(corpus))

    historical = estimate_finding_economics(row, handle="acme")
    assert historical.prior_samples == 2
    assert historical.acceptance_probability >= baseline.acceptance_probability
    assert historical.expected_gross_usd >= baseline.expected_gross_usd
    # Historical frequency can inform exploration, but never masquerades as many real outcomes.
    assert historical.prior_samples < 5
