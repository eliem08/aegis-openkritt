"""OSS scanner bridge — parse real-shaped tool output into Aegis rows (no real tools)."""

from __future__ import annotations

import json

from aegis.ai.tool_bridge import ToolBridge, available_tools
from aegis.ai.tool_registry import TOOLS, tools_for


def test_registry_lanes():
    assert any(t.name == "semgrep" for t in tools_for("code"))
    assert any(t.name == "slither" for t in tools_for("contract"))
    assert any(t.name == "gitleaks" for t in tools_for("secrets"))


def test_available_tools_filters_by_installed(monkeypatch):
    import aegis.ai.tool_bridge as tb
    # only semgrep "installed" (patch the resolver so real venv tools don't leak in)
    monkeypatch.setattr(tb, "resolve_binary",
                        lambda b: "/usr/bin/semgrep" if b == "semgrep" else None)
    avail = {t.name for t in available_tools()}
    assert avail == {"semgrep"}


def _semgrep_out():
    return json.dumps({"results": [
        {"check_id": "python.sqli", "path": "app.py", "start": {"line": 12},
         "extra": {"severity": "ERROR", "message": "SQL injection via string format"}}]})


def _slither_out():
    return json.dumps({"results": {"detectors": [
        {"check": "reentrancy-eth", "impact": "High", "description": "reentrancy in withdraw",
         "elements": [{"source_mapping": {"filename_relative": "V.sol", "lines": [42]}}]}]}})


def _run_map(outputs):
    # a fake process runner keyed by the tool binary basename (argv[0] may be a resolved
    # full path once resolve_binary rewrites it)
    import os
    def run(argv, timeout):
        base = os.path.basename(argv[0]).removesuffix(".exe")
        return outputs.get(base, ""), ""
    return run


def test_semgrep_output_becomes_high_severity_rows():
    from aegis.ai.tool_registry import tools_for
    bridge = ToolBridge(run=_run_map({"semgrep": _semgrep_out()}))
    results = bridge.scan("/repo", tools=tools_for("code")[:1])   # semgrep
    rows = bridge.findings(results)
    assert rows and rows[0]["source"] == "aegis:tool:semgrep"
    assert rows[0]["severity"] == "high" and rows[0]["json_answer"]["line"] == 12
    assert rows[0]["validation_status"] == "unverified"           # never auto-confirmed


def test_slither_output_parsed_for_contract_lane():
    slither = next(t for t in TOOLS if t.name == "slither")
    bridge = ToolBridge(run=_run_map({"slither": _slither_out()}))
    rows = bridge.findings(bridge.scan("0xV", tools=[slither]))
    assert rows and "reentrancy" in rows[0]["json_answer"]["vulnerability_type"]
    assert rows[0]["severity"] == "high" and rows[0]["json_answer"]["file_path"] == "V.sol"


def test_banner_before_json_is_tolerated():
    semgrep = next(t for t in TOOLS if t.name == "semgrep")
    noisy = "Scanning 3 files...\n" + _semgrep_out()
    rows = ToolBridge(run=_run_map({"semgrep": noisy})).scan("/r", tools=[semgrep])
    assert rows[0].findings


def test_tool_crash_is_isolated():
    semgrep = next(t for t in TOOLS if t.name == "semgrep")
    def boom(argv, timeout):
        raise RuntimeError("semgrep not installed")
    results = ToolBridge(run=boom).scan("/r", tools=[semgrep])
    assert results[0].ran is False and "not installed" in results[0].error


def test_empty_output_yields_no_findings():
    semgrep = next(t for t in TOOLS if t.name == "semgrep")
    results = ToolBridge(run=_run_map({"semgrep": ""})).scan("/r", tools=[semgrep])
    assert results[0].findings == []
