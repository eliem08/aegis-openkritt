"""Recently-changed source-file listing."""

from __future__ import annotations

from aegis.ai.fresh_commits import _is_source, recent_source_files


def test_is_source_filters_production_code():
    assert _is_source("packages/next/src/server/image-optimizer.ts")
    assert _is_source("core/Auth.php")
    assert not _is_source("README.md")
    assert not _is_source("packages/next/src/server/__tests__/x.ts")
    assert not _is_source("test/auth/login.go")
    assert not _is_source("vendor/pkg/a.go")


class _GH:
    """Fake GitHub client: a commit list, then per-commit file details."""
    def __init__(self, commits, details):
        self._commits = commits
        self._details = details

    def get(self, url, params=None, timeout=None):
        class _R:
            def __init__(self, payload): self._p = payload
            def json(self): return self._p
        if url.endswith("/commits"):
            return _R(self._commits)
        sha = url.rsplit("/", 1)[-1]
        return _R(self._details[sha])


def test_recent_files_ranked_by_frequency_then_recency():
    commits = [{"sha": "c1"}, {"sha": "c2"}]
    details = {
        "c1": {"files": [{"filename": "src/a.ts"}, {"filename": "src/hot.ts"},
                         {"filename": "docs/x.md"}]},          # md dropped
        "c2": {"files": [{"filename": "src/hot.ts"},           # hot touched twice
                         {"filename": "src/b.ts"},
                         {"filename": "src/__tests__/t.ts"}]},  # test dropped
    }
    files = recent_source_files("a/b", gh_client=_GH(commits, details))
    assert files[0] == "src/hot.ts"                            # most-changed first
    assert set(files) == {"src/hot.ts", "src/a.ts", "src/b.ts"}
    assert all("test" not in f and ".md" not in f for f in files)


def test_recent_files_empty_on_bad_response():
    class _Bad:
        def get(self, *a, **k):
            raise RuntimeError("network")
    assert recent_source_files("a/b", gh_client=_Bad()) == []


def _git(path, args):
    import subprocess
    subprocess.run(["git"] + args, cwd=path, check=True, capture_output=True)


def test_changed_line_ranges_from_real_commit(tmp_path):
    import subprocess
    from aegis.ai.fresh_commits import changed_line_ranges
    repo = tmp_path / "r"; repo.mkdir()
    _git(repo, ["init", "-q"]); _git(repo, ["config", "user.email", "t@t.t"]); _git(repo, ["config", "user.name", "t"])
    (repo / "a.py").write_text("line1\nline2\nline3\n", encoding="utf-8")
    _git(repo, ["add", "-A"]); _git(repo, ["commit", "-qm", "init"])
    (repo / "a.py").write_text("line1\nNEW-A\nNEW-B\nline2\nline3\n", encoding="utf-8")
    _git(repo, ["add", "-A"]); _git(repo, ["commit", "-qm", "change"])
    ranges = changed_line_ranges(repo, "a.py")
    assert ranges and any(a <= 2 <= b or a == 2 for a, b in ranges)   # new lines around 2-3


def test_changed_lines_hint_renders_or_empty():
    from aegis.ai.fresh_commits import changed_lines_hint
    assert changed_lines_hint([]) == ""
    t = changed_lines_hint([(10, 14), (20, 20)])
    assert "Recently changed lines" in t and "L10-14" in t and "L20" in t
