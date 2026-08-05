"""Fresh-commit watcher: detect repos that shipped new commits since last poll."""

from __future__ import annotations

from aegis.ai.fresh_watch import FreshCommitWatcher, WatchState


class _FakeResp:
    def __init__(self, payload):
        self._p = payload

    def json(self):
        return self._p


class _FakeGH:
    """Returns a scripted latest-SHA per repo; advance() rewrites them for the next poll."""
    def __init__(self, shas: dict):
        self._shas = shas

    def advance(self, shas: dict):
        self._shas.update(shas)

    def get(self, url, params=None, timeout=None):
        repo = url.split("/repos/")[1].rsplit("/commits", 1)[0]
        sha = self._shas.get(repo, "")
        return _FakeResp([{"sha": sha}] if sha else [])


def test_first_sighting_not_fresh_by_default(tmp_path):
    st = WatchState(tmp_path / "s.json")
    gh = _FakeGH({"a/b": "sha1"})
    fresh = FreshCommitWatcher(gh, st).poll(["a/b"])
    assert fresh == []                       # no baseline -> not reported
    assert st.last_sha("a/b") == "sha1"      # but recorded


def test_new_commit_detected(tmp_path):
    st = WatchState(tmp_path / "s.json")
    gh = _FakeGH({"a/b": "sha1"})
    w = FreshCommitWatcher(gh, st)
    w.poll(["a/b"])                          # baseline sha1
    gh.advance({"a/b": "sha2"})              # a new commit shipped
    fresh = w.poll(["a/b"])
    assert len(fresh) == 1
    assert fresh[0].new_sha == "sha2" and fresh[0].prev_sha == "sha1"


def test_no_change_not_fresh(tmp_path):
    st = WatchState(tmp_path / "s.json")
    gh = _FakeGH({"a/b": "sha1"})
    w = FreshCommitWatcher(gh, st)
    w.poll(["a/b"])
    assert w.poll(["a/b"]) == []             # same sha -> nothing fresh


def test_first_seen_is_fresh_opt_in(tmp_path):
    st = WatchState(tmp_path / "s.json")
    gh = _FakeGH({"a/b": "sha1"})
    fresh = FreshCommitWatcher(gh, st).poll(["a/b"], first_seen_is_fresh=True)
    assert len(fresh) == 1 and fresh[0].prev_sha == ""


def test_state_persists_across_instances(tmp_path):
    p = tmp_path / "s.json"
    gh = _FakeGH({"a/b": "sha1"})
    FreshCommitWatcher(gh, WatchState(p)).poll(["a/b"])
    # a fresh watcher instance loads the saved baseline
    gh.advance({"a/b": "sha9"})
    fresh = FreshCommitWatcher(gh, WatchState(p)).poll(["a/b"])
    assert len(fresh) == 1 and fresh[0].new_sha == "sha9"
