"""Publish the Aegis research playbooks into a running open·kritt:

    python -m aegis.hunt.publish_workflows

Needs AEGIS_OPENKRITT_URL. Idempotent — existing workflows (by name) are skipped.
"""

from __future__ import annotations

import sys

from ..api.config import ControlPlaneConfig
from ..env import load_dotenv
from .workflows import publish_workflows


def main() -> int:
    load_dotenv()
    client = ControlPlaneConfig.from_env().build_openkritt_client()
    if client is None:
        print("error: set AEGIS_OPENKRITT_URL to a running open·kritt backend.", file=sys.stderr)
        return 2
    try:
        result = publish_workflows(client)
    finally:
        client.close()
    for w in result["created"]:
        print(f"created workflow {w['id']}: {w['name']}")
    for name in result["skipped"]:
        print(f"skipped (exists): {name}")
    print(f"{len(result['created'])} created, {len(result['skipped'])} skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
