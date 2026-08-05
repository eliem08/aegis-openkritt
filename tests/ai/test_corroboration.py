"""Cross-engine corroboration: agreement between distinct engines at one location."""

from __future__ import annotations

from aegis.ai.corroboration import corroborate, engine_of


def _row(source, path, line):
    return {"source": source, "json_answer": {"file_path": path, "line": line}}


def test_engine_normalization():
    assert engine_of({"source": "aegis:tool:semgrep"}) == "scanner:semgrep"
    assert engine_of({"source": "aegis:skill:x-ray"}) == "skill:x-ray"
    assert engine_of({"source": ""}) == "llm"
    assert engine_of({}) == "llm"


def test_three_engines_same_location_corroborate():
    rows = [
        _row("", "app/x.rb", 42),                    # llm
        _row("aegis:tool:brakeman", "app/x.rb", 43),  # scanner, within window
        _row("aegis:skill:security-review", "app/x.rb", 41),  # skill, within window
    ]
    corroborate(rows)
    for r in rows:
        assert r["corroboration"]["count"] == 3
        assert set(r["corroboration"]["engines"]) == {"llm", "scanner:brakeman", "skill:security-review"}


def test_far_apart_lines_do_not_corroborate():
    rows = [_row("", "x.go", 10), _row("aegis:tool:gosec", "x.go", 90)]
    corroborate(rows)
    assert rows[0]["corroboration"]["count"] == 1
    assert rows[1]["corroboration"]["count"] == 1


def test_different_files_do_not_corroborate():
    rows = [_row("", "a.php", 5), _row("aegis:tool:psalm", "b.php", 5)]
    corroborate(rows)
    assert all(r["corroboration"]["count"] == 1 for r in rows)


def test_same_engine_twice_counts_once():
    # two semgrep hits at one spot is not cross-engine agreement
    rows = [_row("aegis:tool:semgrep", "x.js", 7), _row("aegis:tool:semgrep", "x.js", 8)]
    corroborate(rows)
    assert rows[0]["corroboration"]["count"] == 1


def test_missing_location_is_lone():
    rows = [_row("aegis:tool:trivy", "", 0)]
    corroborate(rows)
    assert rows[0]["corroboration"]["count"] == 1
