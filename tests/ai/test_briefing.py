"""Morning briefing: collect confirmed survivors, rank, render Markdown."""

from __future__ import annotations

import json
from pathlib import Path

from aegis.ai.briefing import build_briefing, collect, render_markdown


def _report(repo, rows):
    return {"scan": {"repository": repo, "commit": "abc123def456"}, "vulnerabilities": rows}


def _row(verdict, cwe, path, line, *, source="aegis:llm", corr=1, engines=None, bounty=None):
    r = {"json_answer": {"vulnerability_type": cwe, "file_path": path, "line": line,
                         "summary": f"{cwe} at {path}"},
         "validation": {"verdict": verdict}, "source": source,
         "corroboration": {"count": corr, "engines": engines or []}}
    if bounty:
        r["enrichment"] = {"bounty_likely": bounty, "bounty_min": bounty // 2, "cvss_score": 7.5}
    return r


def test_collect_only_confirmed(tmp_path: Path):
    (tmp_path / "deepseek_a_b.json").write_text(json.dumps(_report("a/b", [
        _row("confirmed", "CWE-89", "x.py", 5),
        _row("false_positive", "CWE-79", "y.py", 9),
        _row("unresolved", "CWE-22", "z.py", 3),
    ])), encoding="utf-8")
    survivors, stats = collect(tmp_path)
    assert stats["survivors"] == 1 and survivors[0]["cwe"] == "CWE-89"
    assert stats["targets_scanned"] == 1


def test_ranking_corroboration_then_bounty(tmp_path: Path):
    (tmp_path / "deepseek_a_b.json").write_text(json.dumps(_report("a/b", [
        _row("confirmed", "LONE-RICH", "a.py", 1, bounty=9000),
        _row("confirmed", "AGREED", "b.py", 2, corr=3, engines=["llm", "scanner:semgrep", "skill:x"], bounty=100),
    ])), encoding="utf-8")
    survivors, _ = collect(tmp_path)
    assert survivors[0]["cwe"] == "AGREED"        # corroboration wins over raw bounty
    assert survivors[1]["cwe"] == "LONE-RICH"


def test_render_empty_is_honest(tmp_path: Path):
    md = render_markdown([], {"targets_scanned": 12, "survivors": 0, "generated_at": "now"})
    assert "No confirmed survivors" in md and "nothing fabricated" in md


def test_build_writes_file(tmp_path: Path):
    (tmp_path / "deepseek_a_b.json").write_text(json.dumps(_report("a/b", [
        _row("confirmed", "CWE-78", "s.py", 4, corr=2, engines=["llm", "scanner:semgrep"], bounty=1500),
    ])), encoding="utf-8")
    out = tmp_path / "briefing.md"
    info = build_briefing(tmp_path, out)
    assert info["survivors"] == 1 and out.is_file()
    text = out.read_text(encoding="utf-8")
    assert "2 engines agree" in text and "CWE-78" in text and "1,500" in text
