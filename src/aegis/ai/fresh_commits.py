"""Recently-changed source files, for the "recently shipped" hunt edge.

Programs like Vercel pay a bonus for bugs reported within a week of the change
landing, and value regressions caught in newly-shipped code before they spread. That
is the one place automation beats human hunters — speed and coverage on fresh diffs,
not re-auditing hardened code everyone has already picked over.

This module lists the source files touched in the last ``days`` and hands them to the
hunt as a focused file set, so the analysis budget goes to code that just changed.
Read-only: lists commits/diffs, never writes.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

_SOURCE_SUFFIXES = (".go", ".py", ".rb", ".php", ".js", ".ts", ".tsx", ".jsx",
                    ".java", ".cs", ".rs", ".c", ".cc", ".cpp", ".sol")
_SKIP = ("test", "tests", "__tests__", "spec", "example", "examples", "vendor",
         "third_party", "node_modules", "fixtures", "mocks")


def _is_source(path: str) -> bool:
    low = path.lower()
    if not low.endswith(_SOURCE_SUFFIXES):
        return False
    return not any(f"/{s}/" in f"/{low}" or low.startswith(f"{s}/") for s in _SKIP)


def recent_source_files(repository: str, *, gh_client, days: int = 7,
                        max_commits: int = 60) -> list[str]:
    """Distinct production source paths touched in ``repository`` in the last ``days``,
    most-recently-and-frequently changed first. ``gh_client`` is an httpx.Client with
    GitHub headers set."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    try:
        commits = gh_client.get(f"https://api.github.com/repos/{repository}/commits",
                                params={"since": since, "per_page": 100}, timeout=25).json()
    except Exception:
        return []
    if not isinstance(commits, list):
        return []

    touched: dict[str, int] = {}
    order: dict[str, int] = {}
    for rank, commit in enumerate(commits[:max_commits]):
        sha = commit.get("sha") if isinstance(commit, dict) else None
        if not sha:
            continue
        try:
            detail = gh_client.get(f"https://api.github.com/repos/{repository}/commits/{sha}",
                                   timeout=25).json()
        except Exception:
            continue
        for entry in (detail.get("files") or []):
            path = entry.get("filename", "")
            if _is_source(path):
                touched[path] = touched.get(path, 0) + 1
                order.setdefault(path, rank)          # first (most recent) commit seen
    # most-frequently changed first, then most-recent
    return sorted(touched, key=lambda p: (-touched[p], order[p], p))
