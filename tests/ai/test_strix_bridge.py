"""Arm's-length Strix bridge: gating + parsing its run output."""

from __future__ import annotations

from pathlib import Path

from aegis.ai.strix_bridge import StrixBridge


def _run_dir(tmp_path: Path) -> Path:
    run = tmp_path / "strix_runs" / "run-1"
    (run / "vulnerabilities").mkdir(parents=True)
    (run / "vulnerabilities.csv").write_text(
        "id,title,severity,timestamp,file\r\n"
        "v1,SQL Injection in login,critical,t,app/auth.php\r\n"
        "v2,Reflected XSS,medium,t,views/search.php\r\n", encoding="utf-8")
    (run / "vulnerabilities" / "v1.md").write_text(
        "# SQLi\n**CWE:** CWE-89\n## Description\n\nInput in app/auth.php:42 hits a raw query.\n",
        encoding="utf-8")
    return run


def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("AEGIS_ALLOW_STRIX", raising=False)
    b = StrixBridge(cmd_bin="/usr/bin/strix")     # binary present…
    assert not b.enabled                          # …but not opted in
    assert b.run("/tmp/x") is None


def test_enabled_needs_bin_and_flag(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_STRIX", "1")
    assert StrixBridge(cmd_bin="/usr/bin/strix").enabled
    # opted in but no resolvable binary -> not enabled (point at a name that won't resolve)
    monkeypatch.setenv("AEGIS_STRIX_BIN", "strix-does-not-exist-xyz")
    assert not StrixBridge().enabled


def test_parses_csv_findings(tmp_path):
    rows = StrixBridge().to_findings(_run_dir(tmp_path), repository="a/b")
    assert len(rows) == 2
    r = rows[0]
    assert r["json_answer"]["vulnerability_type"] == "SQL Injection in login"
    assert r["json_answer"]["file_path"] == "app/auth.php"
    assert r["json_answer"]["line"] == 42                # pulled from the .md
    assert r["severity"] == "critical"
    assert r["source"] == "aegis:strix:v1"
    assert r["validation_status"] == "unverified"        # cross-checked by Aegis, not trusted


def test_missing_run_dir_is_empty():
    assert StrixBridge().to_findings(None) == []
    assert StrixBridge().to_findings(Path("/nonexistent/run")) == []
