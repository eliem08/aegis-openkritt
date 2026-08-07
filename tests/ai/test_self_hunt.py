"""Self-hunt report shaping stays candidate-only and carries the funnel + audit trail."""

from __future__ import annotations

from types import SimpleNamespace

from aegis.ai.candidate_reduction import reduce_candidates
from aegis.ai.self_hunt import build_report


def _row(tool, rule, path, cwe=None, sev="medium", conf=0.6):
    return {"json_answer": {"vulnerability_type": cwe or rule, "file_path": path, "line": 1,
                            "summary": ""}, "severity": sev,
            "source": f"aegis:tool:{tool}", "confidence": conf,
            "scanner_metadata": {"rule_id": rule, "cwe": cwe}}


def test_build_report_is_candidate_only_and_carries_funnel():
    rows = [_row("bandit", "B110", "src/a.py"),                       # suppressed
            _row("semgrep", "sqli", "src/db.py", cwe="CWE-89", sev="high", conf=0.9)]  # survives
    red = reduce_candidates(rows)
    results = [SimpleNamespace(tool="bandit", ran=True, findings=[rows[0]], error=""),
               SimpleNamespace(tool="semgrep", ran=True, findings=[rows[1]], error="")]
    rep = build_report("owner/repo", "repository-owner self-audit", results, rows, red)

    assert rep["evidence_stage"] == "candidate"
    assert rep["raw_candidate_count"] == 2
    assert rep["survivor_count"] == 1
    assert rep["funnel"]["raw"] == 2
    assert rep["funnel"]["survivors"] == 1
    # the suppressed candidate is retained in aggregate, with its reason
    assert any(k.startswith("low-value-rule") for k in rep["suppressed_summary"])
    # nothing claims reproduction
    assert "reproduced" not in {c.get("stage") for c in rep["survivors"]}
    assert "unverified candidates" in rep["note"]


def test_report_tools_reflect_run_state():
    rows = [_row("semgrep", "x", "src/a.py")]
    red = reduce_candidates(rows)
    results = [SimpleNamespace(tool="semgrep", ran=True, findings=rows, error=""),
               SimpleNamespace(tool="brakeman", ran=True, findings=[], error="not a rails app")]
    rep = build_report("owner/repo", "auth", results, rows, red)
    tools = {t["tool"]: t for t in rep["tools"]}
    assert tools["brakeman"]["count"] == 0 and tools["brakeman"]["error"]
    assert tools["semgrep"]["ran"] is True
