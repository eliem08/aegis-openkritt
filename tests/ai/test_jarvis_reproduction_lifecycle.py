from __future__ import annotations

from types import SimpleNamespace

from aegis.ai.auto_hunt import HuntTarget
from aegis.ai.jarvis_bridge import advance_reproduction, evaluate_finding


def _auth():
    return SimpleNamespace(
        repository="acme/repo",
        allowed=True,
        status="authorized",
        reason="in scope",
        record=SimpleNamespace(scope_snapshot_hash="scope1234"),
    )


def test_reproduced_row_advances_sequentially_with_evidence(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_JARVIS_STATE_DB", str(tmp_path / "jarvis.sqlite3"))
    row = {
        "source": "aegis:llm",
        "agreement": 3,
        "samples": 3,
        "validation": {"verdict": "confirmed", "confidence": 0.95},
        "reachability": {"verdict": "reachable"},
        "json_answer": {
            "vulnerability_type": "CWE-89",
            "summary": "SQL injection",
            "file_path": "app.py",
            "line": 9,
        },
    }
    target = HuntTarget(repository="acme/repo", handle="acme", reward_ceiling=5000)
    evaluate_finding(
        row,
        target,
        _auth(),
        report_root=tmp_path,
        model_egress_allowed=True,
        human_hour_cost_usd=0,
        local_lab_available=True,
    )
    assert row["jarvis"]["stage"] == "source_supported"
    assert row["jarvis"]["quality_policy"][1]["approved"] is True

    row["reproduction"] = {
        "verdict": "reproduced",
        "summary": "deterministic local oracle observed the vulnerable behavior",
        "attempts": 1,
        "instance": "http://127.0.0.1:49152",
    }
    stage = advance_reproduction(row, "acme/repo", report_root=tmp_path)
    assert stage.value == "locally_reproduced"
    assert row["jarvis"]["stage"] == "locally_reproduced"
    assert [item["kind"] for item in row["jarvis"]["reproduction_evidence"]] == [
        "runtime_observation",
        "deterministic_oracle",
        "local_reproduction",
    ]


def test_failed_reproduction_does_not_advance_stage(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_JARVIS_STATE_DB", str(tmp_path / "jarvis.sqlite3"))
    row = {
        "validation": {"verdict": "confirmed"},
        "json_answer": {"vulnerability_type": "CWE-79", "file_path": "x.py", "line": 1},
        "jarvis": {"stage": "source_supported"},
        "reproduction": {"verdict": "not_reproduced", "summary": "negative control"},
    }
    stage = advance_reproduction(row, "acme/repo", report_root=tmp_path)
    assert stage.value == "source_supported"
    assert row["jarvis"]["stage"] == "source_supported"
