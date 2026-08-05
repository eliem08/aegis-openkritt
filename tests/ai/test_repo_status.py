"""Retired/archived/demo repo detection — keep junk survivors out of the hunt."""

from __future__ import annotations

from pathlib import Path

from aegis.ai.repo_status import retirement_status


def _repo(tmp_path: Path, readme: str) -> Path:
    (tmp_path / "README.md").write_text(readme, encoding="utf-8")
    return tmp_path


def test_retired_sample_app(tmp_path: Path):
    r = retirement_status(_repo(tmp_path, "# Warning\nThis sample SP has been retired. "
                                          "It should not be used for production."))
    assert r["retired"] and "retired" in r["reason"].lower()


def test_deprecated_and_unmaintained(tmp_path: Path):
    for txt in ("This library is deprecated.", "no longer maintained — use X instead",
                "This repo is archived and abandoned."):
        assert retirement_status(_repo(tmp_path, txt))["retired"], txt


def test_live_repo_not_flagged(tmp_path: Path):
    r = retirement_status(_repo(tmp_path, "# CoolLib\nA fast, production-ready toolkit. "
                                          "See examples/ for sample usage."))
    assert not r["retired"]           # "sample usage"/"examples" alone must not trip it


def test_github_archived_flag_is_authoritative(tmp_path: Path):
    r = retirement_status(_repo(tmp_path, "# Totally active project"), archived=True)
    assert r["retired"] and "archived" in r["reason"].lower()


def test_no_readme(tmp_path: Path):
    assert not retirement_status(tmp_path)["retired"]
