"""Compatibility shim for the canonical :mod:`aegis.env` loader.

New code should import from ``aegis.env``. This module remains only so older callers/tests do not
break; it contains no independent parsing implementation.
"""

from __future__ import annotations

import os
from pathlib import Path

from .env import find_dotenv, parse_env
from .env import load_dotenv as _canonical_load_dotenv


def _parse_line(line: str) -> tuple[str, str] | None:
    """Backward-compatible single-line parser implemented by the canonical parser."""
    parsed = parse_env(line)
    return next(iter(parsed.items())) if parsed else None


def load_dotenv(path: str | Path | None = None, *, override: bool = False) -> list[str]:
    """Load through :mod:`aegis.env` and return only names newly applied to ``os.environ``."""
    before = set(os.environ)
    parsed = _canonical_load_dotenv(path, override=override)
    if override:
        return list(parsed)
    return [key for key in parsed if key not in before]


__all__ = ["find_dotenv", "load_dotenv", "parse_env"]
