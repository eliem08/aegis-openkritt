"""Minimal, dependency-free ``.env`` loader.

Aegis reads all secrets/config from the environment (API tokens, model keys, signing keys). This
loads a ``.env`` file into ``os.environ`` so the CLIs and the API pick those up without the
operator having to export every variable by hand.

Deliberate properties:
  * **Real environment wins.** By default an already-set variable is NOT overwritten, so an
    explicit ``export`` or CI secret always takes precedence over the file.
  * **Never logs values.** It returns only the *names* it set; callers may log names, never values.
  * **No dependency.** Parses ``KEY=VALUE`` lines, tolerating ``export`` prefixes, ``#`` comments,
    blank lines, and single/double-quoted values. Malformed lines are skipped, not fatal.

Security: a ``.env`` holding live tokens must stay out of version control (it is gitignored here).
This loader only reads it into the current process; it never writes, prints, or transmits values.
"""

from __future__ import annotations

import os
from pathlib import Path


def find_dotenv(start: str | Path | None = None) -> Path | None:
    """Locate a ``.env`` walking up from ``start`` (default: cwd) to the filesystem root."""
    cur = Path(start or Path.cwd()).resolve()
    for d in (cur, *cur.parents):
        cand = d / ".env"
        if cand.is_file():
            return cand
    return None


def _parse_line(line: str) -> tuple[str, str] | None:
    s = line.strip()
    if not s or s.startswith("#") or "=" not in s:
        return None
    if s.startswith("export "):
        s = s[len("export "):].lstrip()
    key, _, val = s.partition("=")
    key = key.strip()
    if not key or not key.replace("_", "").isalnum():
        return None
    val = val.strip()
    # strip a trailing inline comment only for unquoted values
    if val[:1] in ("'", '"'):
        quote = val[0]
        end = val.find(quote, 1)
        val = val[1:end] if end > 0 else val[1:]
    else:
        val = val.split(" #", 1)[0].strip()
    return key, val


def load_dotenv(path: str | Path | None = None, *, override: bool = False) -> list[str]:
    """Load ``path`` (or the nearest ``.env``) into ``os.environ``. Returns the list of variable
    NAMES that were set (never values). ``override=False`` keeps any already-set variable."""
    p = Path(path) if path else find_dotenv()
    if not p or not p.is_file():
        return []
    loaded: list[str] = []
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return []
    for line in text.splitlines():
        kv = _parse_line(line)
        if not kv:
            continue
        key, val = kv
        if not override and key in os.environ:
            continue
        os.environ[key] = val
        loaded.append(key)
    return loaded
