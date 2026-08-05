"""Cross-engine corroboration: agreement between independent engines is strong signal.

The hunt now folds candidates from three kinds of engine into one report — the DeepSeek
LLM ensemble, deterministic OSS scanners (semgrep/brakeman/gosec/psalm/slither/...), and
arm's-length skills. When two or more DISTINCT engines independently flag the same file
and (nearby) line, the probability that it is a real bug jumps far above any single
engine's base rate. This tags each candidate with how many distinct engines corroborate
its location, so ranking and the UI can surface agreement.

Pure and deterministic: it only reads the rows' source + json_answer location. It never
invents a finding — corroboration is a confidence signal layered on candidates that still
must pass the citation validator.
"""

from __future__ import annotations

import os
from collections import defaultdict

_LINE_WINDOW = 3   # rows within this many lines of each other count as the same location


def engine_of(row: dict) -> str:
    """Normalize a row's origin to a distinct engine id (llm / tool:x / skill:x)."""
    src = str(row.get("source") or "").lower()
    if ":tool:" in src:
        return "scanner:" + src.split(":tool:")[-1]
    if ":skill:" in src:
        return "skill:" + src.split(":skill:")[-1]
    return "llm"


def _key(row: dict) -> tuple[str, int]:
    a = row.get("json_answer") or {}
    path = os.path.basename(str(a.get("file_path") or "")).lower()
    try:
        line = int(a.get("line") or 0)
    except (TypeError, ValueError):
        line = 0
    return path, line


def corroborate(rows: list[dict]) -> list[dict]:
    """Annotate each row in place with a ``corroboration`` dict: the set of DISTINCT
    engines that flagged the same file within +/- _LINE_WINDOW lines. Returns the rows.

    A row corroborated by N distinct engines gets {"count": N, "engines": [...]}; a lone
    row gets count 1. Grouping is by file basename + a small line window so a scanner's
    off-by-a-few line number still matches the LLM's."""
    # bucket rows by file, then cluster by line proximity
    by_file: dict[str, list[tuple[int, dict]]] = defaultdict(list)
    for row in rows:
        path, line = _key(row)
        if not path:
            row["corroboration"] = {"count": 1, "engines": [engine_of(row)]}
            continue
        by_file[path].append((line, row))

    for path, entries in by_file.items():
        entries.sort(key=lambda e: e[0])
        for line, row in entries:
            engines = set()
            for other_line, other in entries:
                if abs(other_line - line) <= _LINE_WINDOW:
                    engines.add(engine_of(other))
            row["corroboration"] = {"count": len(engines), "engines": sorted(engines)}
    return rows


def corroboration_of(row: dict) -> dict:
    return row.get("corroboration") or {"count": 1, "engines": [engine_of(row)]}
