"""Whole-repository checkout for the autonomous hunt.

The GitHub-API source could only afford to read the handful of files it had already
decided to analyze — selection was therefore blind to file *contents* beyond a small
sampled pool, and every listing burned rate limit. Cloning once removes both limits:
every file is local, reads are free, so content-aware selection can weigh the whole
tree, and later stages (proof-of-concept reproduction, patch diffing) have a real
working tree to operate on.

Read-only by intent: a shallow clone of public source, never executed, never pushed.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

_CLONE_TIMEOUT = 900          # seconds; large repos over a slow link
_DEFAULT_CACHE = Path("reports") / "clones"


class RepoCloneError(RuntimeError):
    """The repository could not be cloned or refreshed."""


def _run(args: list[str], cwd: Path | None = None, timeout: int = _CLONE_TIMEOUT):
    """Run git without a shell, with output captured and a hard timeout."""
    try:
        return subprocess.run(
            args, cwd=str(cwd) if cwd else None, capture_output=True,
            text=True, timeout=timeout, check=False,
        )
    except FileNotFoundError as exc:                      # git missing
        raise RepoCloneError("git executable not found on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise RepoCloneError(f"git timed out after {timeout}s") from exc


@dataclass
class CloneResult:
    path: Path
    commit: str
    reused: bool


def clone_repository(repository: str, *, cache_dir: str | Path | None = None,
                     refresh: bool = False, depth: int = 1,
                     token: str = "") -> CloneResult:
    """Shallow-clone ``owner/repo`` into the cache and return its path + head commit.

    An existing clone is reused (optionally refreshed) so repeated hunts on the same
    target cost nothing. ``token`` is used for the fetch only and is never written to
    the clone's config — the remote is rewritten to the plain URL afterwards.
    """
    if repository.count("/") != 1 or not all(repository.split("/")):
        raise RepoCloneError(f"expected owner/repo, got {repository!r}")
    root = Path(cache_dir) if cache_dir else _DEFAULT_CACHE
    root.mkdir(parents=True, exist_ok=True)
    target = root / repository.replace("/", "__")

    public_url = f"https://github.com/{repository}.git"
    fetch_url = f"https://x-access-token:{token}@github.com/{repository}.git" if token else public_url

    if target.is_dir() and (target / ".git").is_dir():
        if refresh:
            result = _run(["git", "fetch", "--depth", str(depth), "origin"], cwd=target)
            if result.returncode == 0:
                _run(["git", "reset", "--hard", "FETCH_HEAD"], cwd=target)
        return CloneResult(path=target, commit=head_commit(target), reused=True)

    if target.exists():                                   # stale non-git dir
        shutil.rmtree(target, ignore_errors=True)

    result = _run(["git", "clone", "--depth", str(depth), "--single-branch",
                   "--no-tags", fetch_url, str(target)])
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        # never echo the token back in an error message
        message = (detail[-1] if detail else "git clone failed").replace(token or "\0", "***")
        raise RepoCloneError(f"clone of {repository} failed: {message}")

    if token:                                             # drop credential from config
        _run(["git", "remote", "set-url", "origin", public_url], cwd=target)
    return CloneResult(path=target, commit=head_commit(target), reused=False)


def head_commit(path: Path) -> str:
    result = _run(["git", "rev-parse", "HEAD"], cwd=path, timeout=60)
    return (result.stdout or "").strip() if result.returncode == 0 else ""


class LocalRepoSource:
    """Fetcher over a local checkout, interface-compatible with ``GitHubSource``.

    ``hunt_repository`` only needs ``list_paths`` and ``read``; backing those with a
    clone means unlimited, free reads and no API rate limit.
    """

    def __init__(self, root: str | Path, commit: str = ""):
        self._root = Path(root).resolve()
        self._commit = commit or head_commit(self._root)

    @property
    def root(self) -> Path:
        return self._root

    def list_paths(self, repository: str = "") -> tuple[list[str], str]:
        """Every tracked-looking file path, POSIX-relative to the checkout root."""
        paths: list[str] = []
        for dirpath, dirnames, filenames in os.walk(self._root):
            dirnames[:] = [d for d in dirnames if d != ".git"]
            base = Path(dirpath)
            for name in filenames:
                rel = (base / name).relative_to(self._root).as_posix()
                paths.append(rel)
        paths.sort()                                       # deterministic ordering
        return paths, self._commit

    def read(self, repository: str, path: str) -> str:
        target = self._safe(path)
        return target.read_text(encoding="utf-8", errors="replace")

    def _safe(self, path: str) -> Path:
        """Resolve inside the checkout; refuse traversal outside it."""
        candidate = (self._root / path).resolve()
        try:
            candidate.relative_to(self._root)
        except ValueError as exc:
            raise RepoCloneError(f"path escapes the checkout: {path!r}") from exc
        return candidate

    def close(self) -> None:                               # symmetry with GitHubSource
        return None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
