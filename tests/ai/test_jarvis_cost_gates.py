from __future__ import annotations

import json

from aegis.ai.enrich import enrich_report
from aegis.ai.repro_hook import _jarvis_reproduction_allowed
from aegis.ai.triager import triage_report


class CountingClient:
    def __init__(self, response=None):
        self.calls = 0
        self.response = response or {
            "verdict": "pass",
            "scope_ok": True,
            "attacker_realistic": True,
            "corrected_severity": "high",
            "reason": "defensible",
            "prerequisites": [],
        }

    def complete_json(self, _messages):
        self.calls += 1
        return dict(self.response)


def _row(*, escalate: bool) -> dict:
    return {
        "validation": {"verdict": "confirmed"},
        "severity": "high",
        "json_answer": {
            "vulnerability_type": "CWE-89",
            "summary": "SQL injection",
            "file_path": "app.py",
            "line": 3,
        },
        "jarvis": {
            "should_escalate": escalate,
            "quality_policy": [
                {"approved": escalate, "reason": "authorized" if escalate else "deferred"},
                {"approved": escalate, "reason": "authorized" if escalate else "deferred"},
                {"approved": escalate, "reason": "authorized" if escalate else "deferred"},
            ],
        },
    }


def test_enrichment_skips_jarvis_deferred_rows(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps({"scan": {}, "vulnerabilities": [_row(escalate=False)]}),
        encoding="utf-8",
    )
    client = CountingClient()
    result = enrich_report(report, client)
    assert result == {"enriched": 0, "jarvis_deferred": 1}
    assert client.calls == 0


def test_enrichment_calls_model_for_escalated_row(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps({"scan": {}, "vulnerabilities": [_row(escalate=True)]}),
        encoding="utf-8",
    )
    client = CountingClient(
        {
            "trust_model_holds": True,
            "trust_model": "remote attacker",
            "cvss_score": 8.0,
            "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
            "severity_band": "high",
            "chain_required": False,
            "preconditions": "none",
            "exploit_practicality": "trivial",
            "likely_duplicate": False,
            "prior_art": "",
            "bounty_min": 500,
            "bounty_likely": 1500,
            "bounty_reasoning": "program tier",
            "remediation": "parameterize query",
        }
    )
    result = enrich_report(report, client)
    assert result["enriched"] == 1
    assert client.calls == 1


def test_reproduction_requires_jarvis_reproduction_decision():
    assert _jarvis_reproduction_allowed(_row(escalate=True)) is True
    assert _jarvis_reproduction_allowed(_row(escalate=False)) is False
    row = _row(escalate=True)
    row["jarvis"]["quality_policy"][1]["approved"] = False
    assert _jarvis_reproduction_allowed(row) is False


def test_triager_does_not_call_model_for_preannotated_deferred_row(monkeypatch):
    # Avoid rebuilding the registry/authorization in this focused cost test; return a small
    # decision object that exercises the same live triage branch.
    class Decision:
        should_escalate = False

    monkeypatch.setattr("aegis.ai.triager._jarvis_quality_gate", lambda _report, _row: Decision())
    row = _row(escalate=False)
    report = {"scan": {"repository": "acme/repo"}, "vulnerabilities": [row]}
    client = CountingClient()
    summary = triage_report(report, client)
    assert summary["jarvis_deferred"] == 1
    assert summary["reviewed"] == 0
    assert client.calls == 0
    assert row["validation"]["verdict"] == "confirmed"
