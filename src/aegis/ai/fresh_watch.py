"""Fresh-commit watcher: hunt newly-shipped code before anyone else sees it.

The strongest real-world edge in bug bounty is speed on fresh code — a bug introduced by
this morning's commit hasn't been looked at by the crowd yet. Aegis already knows how to
hunt a focused diff (fresh_commits.recent_source_files + RepoHuntConfig.changed_ranges +
--since-days); this is the missing loop that watches a set of repos, remembers the last
commit it saw for each, and reports which have shipped new code since — so the hunt can be
pointed at just the change.

Read-only: it lists each repo's latest commit via the GitHub API. State (last-seen SHA per
repo) persists to a small JSON file so the watcher survives restarts. Pure enough to test
with a fake client — no network in the tests.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FreshCommit:
    repository: str
    new_sha: str
    prev_sha: str
    branch: str = ""


class WatchState:
    """Last-seen commit SHA per repo, persisted to JSON."""

    def __init__(self, path: str | Path = "reports/fresh_watch_state.json") -> None:
        self._path = Path(path)
        self._seen: dict[str, str] = {}
        if self._path.is_file():
            try:
                self._seen = {k: str(v) for k, v in json.loads(self._path.read_text()).items()}
            except Exception:
                self._seen = {}

    def last_sha(self, repo: str) -> str:
        return self._seen.get(repo, "")

    def record(self, repo: str, sha: str) -> None:
        self._seen[repo] = sha

    def save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._seen, indent=1), encoding="utf-8")


def latest_sha(repository: str, *, gh_client, branch: str = "") -> tuple[str, str]:
    """(sha, branch) of the repo's latest commit on its default (or given) branch."""
    url = f"https://api.github.com/repos/{repository}/commits"
    params = {"per_page": 1}
    if branch:
        params["sha"] = branch
    try:
        resp = gh_client.get(url, params=params, timeout=20)
        data = resp.json()
    except Exception:
        return "", branch
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return str(data[0].get("sha", "")), branch
    return "", branch


@dataclass
class FreshCommitWatcher:
    """Poll a set of repos and report the ones that shipped new commits since last poll."""
    gh_client: object
    state: WatchState = field(default_factory=WatchState)

    def poll(self, repositories: list[str], *, first_seen_is_fresh: bool = False
             ) -> list[FreshCommit]:
        """Return the repos whose latest SHA changed since the last poll, updating state.

        A repo seen for the FIRST time is not reported as fresh by default (we have no
        baseline — reporting it would hunt the whole repo, not a diff). Set
        ``first_seen_is_fresh`` to treat first sightings as fresh too."""
        fresh: list[FreshCommit] = []
        for repo in repositories:
            sha, branch = latest_sha(repo, gh_client=self.gh_client)
            if not sha:
                continue
            prev = self.state.last_sha(repo)
            is_new = (prev and sha != prev) or (not prev and first_seen_is_fresh)
            if is_new:
                fresh.append(FreshCommit(repository=repo, new_sha=sha, prev_sha=prev, branch=branch))
            self.state.record(repo, sha)
        self.state.save()
        return fresh
