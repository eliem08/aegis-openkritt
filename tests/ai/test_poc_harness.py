"""PoC scaffold generation."""

from __future__ import annotations

import json

from aegis.ai.poc_harness import (
    build_poc, build_pocs_from_report, detect_compose_hint,
)


def _row(verdict="confirmed", **over):
    answer = {
        "vulnerability_type": "CWE-639: IDOR",
        "summary": "cross-user session read",
        "file_path": "plugins/X/API.php", "line": 42,
        "explanation": "the lookup uses a client id without an ownership check",
        "trigger_flow": "GET /index.php?module=X&idSession=<other user's id>",
        "malicious_actor": "any authenticated low-priv user",
        "impact": "reads another user's session data",
        "severity": "high",
    }
    answer.update(over)
    return {"json_answer": answer, "severity": "high",
            "validation": {"verdict": verdict,
                           "trust_model": "any logged-in user; needs only their own session"}}


def test_build_poc_writes_three_artifacts(tmp_path):
    art = build_poc(_row(), repository="matomo-org/matomo", out_dir=tmp_path,
                    program_handle="matomo", commit="abc123", compose_hint="docker compose up -d")
    assert art.report_path.is_file() and art.repro_path.is_file() and art.runbook_path.is_file()
    report = art.report_path.read_text(encoding="utf-8")
    assert "CWE-639" in report
    assert "matomo-org/matomo" in report and "`matomo`" in report
    assert "GET /index.php" in report                    # entry point carried through
    assert "any logged-in user" in report                # trust model carried through
    assert "abc123" in report                            # affected commit filled in


def test_report_warns_when_not_confirmed(tmp_path):
    art = build_poc(_row(verdict="unresolved"), repository="a/b", out_dir=tmp_path)
    report = art.report_path.read_text(encoding="utf-8")
    assert "not confirmed" in report.lower()
    assert "unresolved" in report.lower()


def test_repro_script_is_inert_by_default(tmp_path):
    art = build_poc(_row(), repository="a/b", out_dir=tmp_path)
    repro = art.repro_path.read_text(encoding="utf-8")
    # the skeleton must refuse to run until a human edits the target
    assert "127.0.0.1:8080" in repro
    assert "set TARGET to your own local instance" in repro


def test_runbook_uses_compose_when_available(tmp_path):
    with_compose = build_poc(_row(), repository="a/b", out_dir=tmp_path / "c",
                             compose_hint="docker compose up -d")
    assert "docker compose up -d" in with_compose.runbook_path.read_text(encoding="utf-8")
    without = build_poc(_row(), repository="a/b", out_dir=tmp_path / "n")
    assert "No compose file" in without.runbook_path.read_text(encoding="utf-8")


def test_detect_compose_hint(tmp_path):
    assert detect_compose_hint(tmp_path) is None
    (tmp_path / "docker-compose.yml").write_text("services: {}", encoding="utf-8")
    assert detect_compose_hint(tmp_path) == "docker compose up -d"


def test_build_from_report_only_confirmed_by_default(tmp_path):
    report = {
        "scan": {"repository": "matomo-org/matomo", "commit": "deadbeef"},
        "vulnerabilities": [
            _row(verdict="confirmed"),
            _row(verdict="unresolved", summary="maybe"),
            _row(verdict="false_positive", summary="nope"),
        ],
    }
    path = tmp_path / "r.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    arts = build_pocs_from_report(path, tmp_path / "poc", program_handle="matomo")
    assert len(arts) == 1                                 # only the confirmed one
    arts_all = build_pocs_from_report(path, tmp_path / "poc2", only_confirmed=False)
    assert len(arts_all) == 3
