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

import re
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


def changed_line_ranges(repo_root, path: str) -> list[tuple[int, int]]:
    """Line ranges added in the most recent commit that touched ``path``, from a local
    clone's git. Lets the hunt tell the generator which lines are NEW — fresh
    regressions in just-shipped code are the winnable ones. Empty on any error."""
    import subprocess
    from pathlib import Path
    try:
        out = subprocess.run(
            ["git", "log", "-1", "--unified=0", "--format=", "--", path],
            cwd=str(Path(repo_root)), capture_output=True, text=True, timeout=60)
    except Exception:
        return []
    ranges: list[tuple[int, int]] = []
    for line in (out.stdout or "").splitlines():
        if not line.startswith("@@"):
            continue
        # @@ -a,b +c,d @@  -> the new-side hunk is c..c+d-1
        m = re.search(r"\+(\d+)(?:,(\d+))?", line)
        if m:
            start = int(m.group(1))
            count = int(m.group(2)) if m.group(2) is not None else 1
            if count > 0:
                ranges.append((start, start + count - 1))
    return ranges


def changed_lines_hint(ranges: list[tuple[int, int]]) -> str:
    """A prompt block flagging the just-changed lines to focus on."""
    if not ranges:
        return ""
    spans = ", ".join(f"L{a}-{b}" if b > a else f"L{a}" for a, b in ranges[:30])
    return ("\n## Recently changed lines (focus here)\n"
            "These lines were added/modified in the most recent commit — regressions in "
            "freshly shipped code are the highest-value target. Prioritize a weakness "
            "introduced or left unguarded in: " + spans + ".")

