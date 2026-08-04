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
