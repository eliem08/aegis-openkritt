"""Minimal, dependency-free ``.env`` loader.

Reads ``KEY=VALUE`` lines from a ``.env`` file into ``os.environ``. By default it
does **not** override variables already set in the real environment, so explicit
CI/production settings always win.

Supported syntax: blank lines, ``# comment`` lines, optional ``export``, quoted
values, and shell-style trailing comments on *unquoted* values (``A=x # note``).
A literal ``#`` that is part of a value should be quoted. Values are never logged.
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
        if value[:1] in ("'", '"'):
            quote = value[0]
            end = value.find(quote, 1)
            value = value[1:end] if end > 0 else value[1:]
        else:
            value = value.split(" #", 1)[0].strip()
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
    """Load a ``.env`` file into ``os.environ`` and return its parsed mapping."""
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
