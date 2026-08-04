"""Aegis-native per-finding triage enrichment."""

from __future__ import annotations

import json

from aegis.ai.enrich import FindingEnrichment, enrich_finding, enrich_report


def _row(**over):
    r = {"json_answer": {"vulnerability_type": "CWE-287", "severity": "high",
                         "summary": "auth bypass", "explanation": "no check",
                         "file_path": "a.php", "line": 10, "trigger_flow": "POST /x",
                         "malicious_actor": "anon"},
         "agreement": 4, "samples": 5, "severity": "high",
         "validation": {"verdict": "confirmed"}}
    r.update(over)
    return r


def _enrichment(**over):
    base = {"trust_model_holds": True, "trust_model": "unauth remote caller",
            "cvss_score": 8.1, "cvss_vector": "CVSS:4.0/AV:N/AC:L", "severity_band": "high",
            "chain_required": False, "preconditions": "none",
            "exploit_practicality": "trivial", "likely_duplicate": False, "prior_art": "",
            "bounty_min": 777, "bounty_likely": 1777, "bounty_reasoning": "matomo high tier",
            "remediation": "add ownership check before the lookup"}
    base.update(over)
    return base


class _Client:
    def __init__(self, payload):
        self._payload = payload
        self.prompts = []
    def complete_json(self, messages, **kwargs):
        self.prompts.append(messages[0]["content"])
        return self._payload


def test_enrich_attaches_triage_block():
    client = _Client(_enrichment())
    row = enrich_finding(client, _row(), program_url="https://hackerone.com/matomo")
    e = row["enrichment"]
    assert e["cvss_score"] == 8.1 and e["bounty_likely"] == 1777
    assert e["remediation"].startswith("add ownership")
    assert "matomo" in client.prompts[0]                     # program url reached the prompt


def test_enrich_survives_bad_model_output():
    class _Bad:
        def complete_json(self, *a, **k): raise RuntimeError("503")
    row = enrich_finding(_Bad(), _row())
    assert "enrichment" not in row                           # left un-enriched, not crashed


def test_enrich_drops_out_of_range_score():
    # cvss > 10 is invalid -> whole enrichment rejected, row untouched
    row = enrich_finding(_Client(_enrichment(cvss_score=42)), _row())
    assert "enrichment" not in row


def test_trust_model_gate_carried_through():
    row = enrich_finding(_Client(_enrichment(trust_model_holds=False,
                                             trust_model="needs admin role")), _row())
    assert row["enrichment"]["trust_model_holds"] is False


def test_enrich_report_only_confirmed(tmp_path):
    report = {"scan": {}, "vulnerabilities": [
        _row(), _row(validation={"verdict": "unresolved"})]}
    p = tmp_path / "r.json"
    p.write_text(json.dumps(report), encoding="utf-8")
    result = enrich_report(p, _Client(_enrichment()), only_confirmed=True)
    assert result["enriched"] == 1                           # only the confirmed one
    data = json.loads(p.read_text(encoding="utf-8"))
    assert "enrichment" in data["vulnerabilities"][0]
    assert "enrichment" not in data["vulnerabilities"][1]


def test_enrichment_model_defaults_are_safe():
    e = FindingEnrichment()
    assert e.trust_model_holds is True and e.cvss_score == 0.0 and e.remediation == ""
