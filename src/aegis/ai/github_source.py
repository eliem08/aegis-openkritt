"""Read-only GitHub source fetcher for the autonomous repository hunt.

Lists a repository's tree and reads individual files over HTTPS. It never clones,
never writes to the remote, and never executes fetched content — a 1.5 GB monorepo
costs one tree listing plus the handful of files actually selected for review.
"""

from __future__ import annotations

import httpx


class GitHubSource:
    def __init__(self, *, token: str = "", client: httpx.Client | None = None,
                 timeout: float = 30.0):
        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._owns = client is None
        self._client = client or httpx.Client(timeout=timeout, headers=headers)
        self._raw = httpx.Client(timeout=timeout)
        self._branch: dict[str, str] = {}

    def list_paths(self, repository: str) -> tuple[list[str], str]:
        """Every blob path in the default branch, plus the head commit sha."""
        meta = self._client.get(f"https://api.github.com/repos/{repository}")
        meta.raise_for_status()
        branch = meta.json().get("default_branch", "master")
        self._branch[repository] = branch

        head = self._client.get(f"https://api.github.com/repos/{repository}/commits/{branch}")
        head.raise_for_status()
        commit = str(head.json().get("sha", ""))

        tree = self._client.get(
            f"https://api.github.com/repos/{repository}/git/trees/{branch}",
            params={"recursive": "1"},
        )
        tree.raise_for_status()
        body = tree.json()
        paths = [item["path"] for item in body.get("tree", []) if item.get("type") == "blob"]
        return paths, commit

    def read(self, repository: str, path: str) -> str:
        branch = self._branch.get(repository, "master")
        resp = self._raw.get(f"https://raw.githubusercontent.com/{repository}/{branch}/{path}")
        resp.raise_for_status()
        return resp.text

    def close(self) -> None:
        if self._owns:
            self._client.close()
        self._raw.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
