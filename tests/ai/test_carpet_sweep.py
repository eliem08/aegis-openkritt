"""Carpet sweep — hit mapping, skip-unchanged, ranking, persistence."""

from __future__ import annotations

from pathlib import Path

import aegis.ai.carpet_sweep as cs
from aegis.ai.registry import Program


class _Clone:
    def __init__(self, commit):
        self.commit = commit
        self.path = "/tmp/x"


class _Res:
    def __init__(self, tool, findings):
        self.tool = tool
        self.findings = findings


class _Bridge:
    rows: list = []

    def __init__(self, timeout=0):
        pass

    def scan(self, path, tools=None):
        return [_Res("semgrep", list(type(self).rows))]

    def findings(self, results):
        out = []
        for r in results:
            out.extend(r.findings)
        return out


def _row(cwe="CWE-434", sev="error", path="upload.php", line=5):
    return {"severity": sev, "json_answer": {"file_path": path, "line": line,
                                             "vulnerability_type": cwe, "summary": "bad upload"}}


def _patch(monkeypatch, commit, rows):
    monkeypatch.setattr("aegis.ai.repo_clone.clone_repository",
                        lambda repo, **k: _Clone(commit))
    _Bridge.rows = rows
    monkeypatch.setattr("aegis.ai.tool_bridge.ToolBridge", _Bridge)


def test_sweep_finds_and_persists(tmp_path, monkeypatch):
    _patch(monkeypatch, "c1", [_row()])
    hits_f, state_f = str(tmp_path / "h.json"), str(tmp_path / "s.json")
    progs = [Program(handle="acme", platform="bugcrowd", targets=["a/b"], reward_ceiling=5000)]
    s = cs.sweep_once(progs, hits_file=hits_f, state_file=state_f)
    assert s["swept"] == 1 and s["new_hits"] == 1 and s["total_hits"] == 1
    hits = cs.load_hits(report_dir=str(tmp_path)) if False else __import__("json").loads(
        Path(hits_f).read_text())
    assert hits[0]["cwe"] == "CWE-434" and hits[0]["reward"] == 5000


def test_skip_unchanged_commit(tmp_path, monkeypatch):
    _patch(monkeypatch, "sameC", [_row()])
    hits_f, state_f = str(tmp_path / "h.json"), str(tmp_path / "s.json")
    progs = [Program(handle="acme", platform="bugcrowd", targets=["a/b"], reward_ceiling=1000)]
    cs.sweep_once(progs, hits_file=hits_f, state_file=state_f)
    s2 = cs.sweep_once(progs, hits_file=hits_f, state_file=state_f)      # same commit
    assert s2["skipped_unchanged"] == 1 and s2["swept"] == 0 and s2["new_hits"] == 0


def test_force_rescans_unchanged(tmp_path, monkeypatch):
    _patch(monkeypatch, "sameC", [_row()])
    hits_f, state_f = str(tmp_path / "h.json"), str(tmp_path / "s.json")
    progs = [Program(handle="acme", platform="bugcrowd", targets=["a/b"], reward_ceiling=1000)]
    cs.sweep_once(progs, hits_file=hits_f, state_file=state_f)
    s2 = cs.sweep_once(progs, hits_file=hits_f, state_file=state_f, force=True)
    assert s2["swept"] == 1                                              # forced despite same commit


def test_ranking_by_reward_times_severity(tmp_path, monkeypatch):
    _patch(monkeypatch, "c1", [_row(cwe="CWE-347", sev="error")])
    hits_f, state_f = str(tmp_path / "h.json"), str(tmp_path / "s.json")
    progs = [
        Program(handle="small", platform="bugcrowd", targets=["a/small"], reward_ceiling=500),
        Program(handle="big", platform="bugcrowd", targets=["a/big"], reward_ceiling=50000),
    ]
    cs.sweep_once(progs, hits_file=hits_f, state_file=state_f)
    hits = __import__("json").loads(Path(hits_f).read_text())
    assert hits[0]["repo"] == "a/big"                                   # higher reward ranks first


def test_inactive_programs_skipped(tmp_path, monkeypatch):
    _patch(monkeypatch, "c1", [_row()])
    hits_f, state_f = str(tmp_path / "h.json"), str(tmp_path / "s.json")
    progs = [Program(handle="off", platform="hackerone", targets=["a/b"], active=False)]
    s = cs.sweep_once(progs, hits_file=hits_f, state_file=state_f)
    assert s["repos_total"] == 0 and s["new_hits"] == 0
