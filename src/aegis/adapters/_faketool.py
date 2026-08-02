"""A tiny fake discovery tool that emits JSONL adapter events.

Stands in for a real pinned binary so the adapter contract and process runner can
be exercised end-to-end without any network. Usage:

    python -m aegis.adapters._faketool <target> [max_results]
"""

from __future__ import annotations

import json
import sys


def _emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    target = argv[0] if argv else "unknown"
    _emit({"kind": "progress", "message": "starting", "target": target})
    _emit({"kind": "asset", "identifier": target, "asset_type": "url"})
    _emit({"kind": "route", "method": "GET", "path": "/health"})
    _emit({"kind": "route", "method": "GET", "path": "/users/{id}",
           "parameters": [{"name": "id", "location": "path"}]})
    _emit({"kind": "technology", "name": "nginx"})
    _emit({"kind": "terminal", "status": "succeeded", "summary": {"assets": 1, "routes": 2}})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
