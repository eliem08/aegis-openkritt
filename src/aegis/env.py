"""Minimal, dependency-free ``.env`` loader.

Reads ``KEY=VALUE`` lines from a ``.env`` file into ``os.environ``. By default it
does **not** override variables already set in the real environment (the real
environment wins), so CI/production secrets are never clobbered by a local file.

Deliberately small and stdlib-only — this project keeps secrets out of prompts
and logs, and a tiny auditable loader is easier to trust than a dependency.
Supported syntax: blank lines, ``# comment`` lines, an optional ``export``
prefix, and single/double-quoted values. Inline comments are *not* stripped, so
values may safely contain ``#`` (e.g. JSON). Values are never logged.
"""

from __future__ import annotations

import os
from pathlib import Path


def parse_env(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        result[key] = value
    return result


def find_dotenv(start: Path | str | None = None, filename: str = ".env") -> Path | None:
    """Walk upward from ``start`` (or cwd) looking for ``filename``."""
    current = Path(start or Path.cwd()).resolve()
    if current.is_file():
        current = current.parent
    for directory in (current, *current.parents):
        candidate = directory / filename
        if candidate.is_file():
            return candidate
    return None


def load_dotenv(
    path: Path | str | None = None,
    *,
    override: bool = False,
    search: bool = True,
) -> dict[str, str]:
    """Load a ``.env`` file into ``os.environ``.

    ``path`` may be a file or a directory. If omitted and ``search`` is true, the
    nearest ``.env`` above the current directory is used. Returns the parsed
    mapping (whether or not each key was applied). Missing file -> ``{}``.
    """
    target: Path | None
    if path is None:
        target = find_dotenv() if search else Path(".env")
    else:
        p = Path(path)
        target = (p / ".env") if p.is_dir() else p
        if not target.is_file() and search:
            target = find_dotenv(target)

    if target is None or not target.is_file():
        return {}

    parsed = parse_env(target.read_text(encoding="utf-8"))
    for key, value in parsed.items():
        if override or key not in os.environ:
            os.environ[key] = value
    return parsed
