"""Whole-repository clone + local file source."""

from __future__ import annotations

import subprocess

import pytest

from aegis.ai.repo_clone import (
    LocalRepoSource, RepoCloneError, clone_repository, head_commit,
)


def _git_repo(path):
    """A tiny real git repo on disk (no network)."""
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.t"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=path, check=True)
    (path / "src").mkdir(exist_ok=True)
    (path / "src" / "auth.go").write_text("package auth\n", encoding="utf-8")
    (path / "README.md").write_text("hi\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=path, check=True)
    return path


def test_local_source_lists_and_reads_files(tmp_path):
    repo = _git_repo(tmp_path / "repo")
    src = LocalRepoSource(repo)
    paths, commit = src.list_paths("acme/repo")
    assert "src/auth.go" in paths and "README.md" in paths
    assert not any(p.startswith(".git/") for p in paths)   # .git never surfaced
    assert len(commit) == 40                                # real head sha
    assert src.read("acme/repo", "src/auth.go") == "package auth\n"


def test_local_source_listing_is_deterministic(tmp_path):
    src = LocalRepoSource(_git_repo(tmp_path / "repo"))
    assert src.list_paths("x")[0] == src.list_paths("x")[0]


def test_local_source_refuses_path_traversal(tmp_path):
    (tmp_path / "secret.txt").write_text("s3cret", encoding="utf-8")
    src = LocalRepoSource(_git_repo(tmp_path / "repo"))
    with pytest.raises(RepoCloneError, match="escapes"):
        src.read("acme/repo", "../secret.txt")


def test_clone_rejects_malformed_repository(tmp_path):
    for bad in ["notaslug", "a/b/c", "/leading", "trailing/"]:
        with pytest.raises(RepoCloneError, match="owner/repo"):
            clone_repository(bad, cache_dir=tmp_path)


def test_clone_reuses_an_existing_checkout(tmp_path, monkeypatch):
    # pre-create the target as a real repo; clone_repository must reuse, not re-clone
    cache = tmp_path / "clones"
    target = _git_repo(cache / "acme__repo")
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        raise AssertionError("should not have shelled out to clone")

    monkeypatch.setattr("aegis.ai.repo_clone._run",
                        lambda args, cwd=None, timeout=900: (
                            calls.append(args) or subprocess.run(
                                args, cwd=cwd, capture_output=True, text=True)))
    result = clone_repository("acme/repo", cache_dir=cache)
    assert result.reused is True
    assert result.path == target
    assert result.commit == head_commit(target)
    assert not any("clone" in a for a in calls)            # no clone was attempted


def test_clone_error_never_echoes_the_token(tmp_path, monkeypatch):
    class Fail:
        returncode = 1
        stdout = ""
        stderr = "fatal: could not read https://x-access-token:ghp_SECRET123@github.com/a/b.git"

    monkeypatch.setattr("aegis.ai.repo_clone._run", lambda *a, **k: Fail())
    with pytest.raises(RepoCloneError) as excinfo:
        clone_repository("acme/repo", cache_dir=tmp_path, token="ghp_SECRET123")
    assert "ghp_SECRET123" not in str(excinfo.value)        # redacted
    assert "***" in str(excinfo.value)
