"""Ingest a HackerOne program into scope + rules + a draft authorization.

    # Offline (uses examples/hackerone.sample.json):
    python examples/hackerone_ingest.py

    # Live (reads YOUR token from the environment; never passed on the CLI):
    set HACKERONE_API_USERNAME=your-handle
    set HACKERONE_API_TOKEN=your-api-token
    python examples/hackerone_ingest.py acme      # a program handle you have access to

Discovery is read-only. This prints the parsed scope and rules-of-engagement and
an UNSIGNED authorization draft. Active testing still requires the control plane
to sign that authorization and a human to confirm the program's rules — and if a
program forbids automated tooling, the draft permits no active actions at all.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import os  # noqa: E402

from aegis.env import load_dotenv  # noqa: E402
from aegis.ingest import ProgramRules, map_program  # noqa: E402

# Load the project's .env so HACKERONE_API_* are available (real env still wins).
load_dotenv(Path(__file__).resolve().parents[1] / ".env")


def load_rules(handle: str | None) -> ProgramRules:
    if os.environ.get("HACKERONE_API_USERNAME") and os.environ.get("HACKERONE_API_TOKEN"):
        from aegis.ingest import HackerOneClient

        with HackerOneClient.from_env() as client:
            if not handle:
                programs = client.list_programs(max_pages=1)
                if not programs:
                    print("no programs available to this account.")
                    sys.exit(1)
                handle = programs[0]["attributes"]["handle"]
            print(f"[live] fetching HackerOne program: {handle}")
            return client.fetch_program_rules(handle)

    print("[offline] no HACKERONE_API_* env vars set; using examples/hackerone.sample.json")
    sample = json.loads((Path(__file__).with_name("hackerone.sample.json")).read_text())
    return map_program(sample["program"], sample["structured_scopes"]["data"])


def main() -> None:
    handle = sys.argv[1] if len(sys.argv) > 1 else None
    rules = load_rules(handle)

    print("=" * 74)
    print(f"program: {rules.name} ({rules.platform}:{rules.handle})")
    print("=" * 74)
    print(f"  bounties        : {rules.offers_bounties}   state: {rules.submission_state}")
    print(f"  automation_ok   : {rules.automation_allowed}")
    print(f"  ai_ok           : {rules.ai_allowed}")
    print(f"  rate cap (rps)  : {rules.rate_limit_rps if rules.rate_limit_rps else '(none stated)'}")
    print(f"  testable by bot : {rules.testable_by_automation}")

    print("\n  in-scope web targets (eligible):")
    for entry in rules.scope_guard_entries():
        print(f"    + {entry}")
    non_web = [a for a in rules.in_scope if not a.is_web]
    if non_web:
        print("  in-scope non-web assets (not auto-tested):")
        for a in non_web:
            print(f"    . {a.raw_asset_type or a.asset_type.value}: {a.identifier}")
    if rules.out_of_scope_hosts():
        print("  out of scope:")
        for h in rules.out_of_scope_hosts():
            print(f"    - {h}")

    print("\n  notes:")
    for n in rules.notes:
        print(f"    * {n}")

    now = datetime.now(timezone.utc)
    draft = rules.to_authorization_draft(
        customer_id="customer-123",
        authorization_id=f"auth-{rules.handle}",
        valid_from=(now - timedelta(hours=1)).isoformat(),
        valid_until=(now + timedelta(days=30)).isoformat(),
    )
    print("\n  authorization draft (UNSIGNED - control plane must sign):")
    print(f"    targets           : {draft['targets']}")
    print(f"    permitted_actions : {draft['permitted_actions']}")
    print(f"    rate_limits       : {draft['rate_limits']}")
    if draft["_meta"]["conflicts"]:
        print("    CONFLICTS (must resolve before active testing):")
        for c in draft["_meta"]["conflicts"]:
            print(f"      ! {c}")
    print("=" * 74)


if __name__ == "__main__":
    main()
