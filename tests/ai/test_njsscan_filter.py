"""njsscan low-precision pattern-only rules are dropped (regex_dos/timing/logic-bypass)."""

from __future__ import annotations

from aegis.ai.tool_registry import _parse_njsscan


def _mk(rule, path="x.js", line=1):
    return {rule: {"files": [{"file_path": path, "match_lines": [line]}],
                   "metadata": {"description": rule}}}


def test_drops_noise_rules_keeps_real_sinks():
    data = {"nodejs": {**_mk("regex_dos"), **_mk("node_timing_attack"),
                       **_mk("node_logic_bypass"), **_mk("sql_injection"),
                       **_mk("node_password")}}
    cwes = {r["json_answer"]["vulnerability_type"] for r in _parse_njsscan(data)}
    assert "regex_dos" not in cwes and "node_timing_attack" not in cwes
    assert "node_logic_bypass" not in cwes
    assert "sql_injection" in cwes and "node_password" in cwes   # real sinks kept


def test_empty_and_malformed_safe():
    assert _parse_njsscan({}) == []
    assert _parse_njsscan(None) == []
    assert _parse_njsscan({"nodejs": {}}) == []
