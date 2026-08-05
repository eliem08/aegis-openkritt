"""Bundled offline Semgrep rules: valid YAML + well-formed, and the bridge points at them."""

from __future__ import annotations

import glob
from pathlib import Path

import yaml

from aegis.ai.tool_bridge import rules_dir


def test_rules_dir_exists_and_has_rulesets():
    d = Path(rules_dir())
    assert d.is_dir()
    assert list(d.glob("*.yml")), "no bundled rulesets found"


def test_all_rulesets_valid():
    files = glob.glob(str(Path(rules_dir()) / "*.yml"))
    assert files
    for f in files:
        doc = yaml.safe_load(Path(f).read_text(encoding="utf-8"))
        assert isinstance(doc, dict) and isinstance(doc.get("rules"), list) and doc["rules"]
        for r in doc["rules"]:
            assert r.get("id"), f
            assert r.get("languages"), r.get("id")
            assert r.get("message"), r.get("id")
            assert "patterns" in r or "pattern" in r or "pattern-either" in r, r.get("id")


def test_semgrep_cmd_uses_bundled_rules():
    from aegis.ai.tool_registry import TOOLS
    semgrep = next(t for t in TOOLS if t.name == "semgrep")
    assert "{rules}" in semgrep.cmd
    # it must format cleanly with both placeholders
    formatted = semgrep.cmd.format(target="/x", rules=rules_dir())
    assert "/x" in formatted and rules_dir() in formatted
