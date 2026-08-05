"""Guarded local-instance reproduction hook: the boundaries hold (no Docker needed)."""

from __future__ import annotations

from aegis.ai.repro_hook import _hypothesis_from_row, maybe_reproduce, repro_enabled


def _report(rows):
    return {"scan": {}, "vulnerabilities": rows}


def _confirmed(cwe="CWE-89", path="app/x.php", line=5):
    return {"json_answer": {"vulnerability_type": cwe, "file_path": path, "line": line,
                            "summary": "sqli", "explanation": "user input in query"},
            "validation": {"verdict": "confirmed"}, "severity": "high"}


def test_off_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("AEGIS_ALLOW_REPRO", raising=False)
    assert not repro_enabled()
    out = maybe_reproduce(tmp_path, _report([_confirmed()]), client=None)
    assert out["attempted"] is False and "opt-in" in out["reason"]


def test_needs_compose(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_REPRO", "1")            # opted in…
    out = maybe_reproduce(tmp_path, _report([_confirmed()]), client=None)
    assert out["attempted"] is False and "docker-compose" in out["reason"]  # …but no compose


def test_needs_confirmed(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_REPRO", "1")
    (tmp_path / "docker-compose.yml").write_text("services: {}", encoding="utf-8")
    unresolved = {"json_answer": {"file_path": "x", "line": 1},
                  "validation": {"verdict": "unresolved"}}
    out = maybe_reproduce(tmp_path, _report([unresolved]), client=None)
    assert out["attempted"] is False and "no confirmed" in out["reason"]


def test_hypothesis_from_row_is_valid():
    h = _hypothesis_from_row(_confirmed())
    assert h.weakness == "CWE-89" and h.line == 5 and h.file_path == "app/x.php"
    assert h.severity == "high"


def test_hypothesis_defaults_when_fields_missing():
    h = _hypothesis_from_row({"json_answer": {}, "validation": {"verdict": "confirmed"}})
    assert h.line == 1 and h.weakness and h.severity == "medium"   # no crash on empty row
