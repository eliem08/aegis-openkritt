"""Skip retired / archived / demo repos — they manufacture non-submittable "survivors".

A real miss: the hunt "confirmed" findings on 18f/identity-saml-rails, whose README's
first line says it is a retired sample app with "confirmed vulnerabilities" that "should
not be used for production." No program pays for known issues in retired demo code, so
hunting it burns budget and fills the briefing with junk.

This reads a cloned repo's README (and, if provided, GitHub's archived flag) and decides
whether it is out of scope as retired/archived/demo. Conservative: it fires only on STRONG
retirement language near the top of the README, not on an incidental "example" mention.
"""

from __future__ import annotations

import re
from pathlib import Path

# strong, unambiguous retirement / not-for-use signals
_RETIRED = [
    r"\bretired\b",
    r"no longer (maintained|supported|in use)",
    r"\b(un|not )maintained\b",
    r"has not been maintained",
    r"\bdeprecated\b",
    r"do not use (this|it|in)",
    r"should not be used (for|in) production",
    r"not (intended |meant )?for production",
    r"this (project|repo|repository|library) is (dead|archived|abandoned)",
    r"\bproof[- ]of[- ]concept only\b",
    r"for (demonstration|educational|teaching) purposes only",
]
_RETIRED_RE = re.compile("|".join(_RETIRED), re.IGNORECASE)
_README_NAMES = ("README.md", "README", "README.rst", "README.txt", "readme.md")


def _read_readme(root: Path, *, head: int = 1500) -> str:
    for name in _README_NAMES:
        f = root / name
        if f.is_file():
            try:
                return f.read_text(encoding="utf-8", errors="replace")[:head]
            except Exception:
                return ""
    # fall back to any top-level README-ish file
    for f in root.glob("[Rr][Ee][Aa][Dd][Mm][Ee]*"):
        if f.is_file():
            try:
                return f.read_text(encoding="utf-8", errors="replace")[:head]
            except Exception:
                return ""
    return ""


def retirement_status(repo_root: str | Path, *, archived: bool | None = None) -> dict:
    """Return {"retired": bool, "reason": str}. ``archived`` (from the GitHub API) is
    authoritative when supplied; otherwise decide from the README's top matter."""
    if archived:
        return {"retired": True, "reason": "GitHub marks this repository archived"}
    text = _read_readme(Path(repo_root))
    m = _RETIRED_RE.search(text)
    if m:
        # a little context around the match, for the skip note
        i = max(0, m.start() - 30)
        snippet = " ".join(text[i:m.end() + 40].split())
        return {"retired": True, "reason": f"README: …{snippet}…"}
    return {"retired": False, "reason": ""}
