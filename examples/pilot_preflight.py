"""Pilot pre-flight: validate the safety plumbing before touching a real target.

    python examples/pilot_preflight.py            # bundled sample program
    python examples/pilot_preflight.py <handle>   # live HackerOne (reads your token)

No network testing happens. It ingests the program, builds an Ed25519-signed
authorization, and checks that the policy gate ALLOWS an in-scope passive action
and DENIES out-of-scope and prohibited actions — plus surfaces any automation/AI
conflicts. Green here = the config is safe to proceed to a supervised run.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis.env import load_dotenv  # noqa: E402
from aegis.ingest import ProgramRules, map_program  # noqa: E402
from aegis.policy import (  # noqa: E402
    ActionRequest,
    Authorization,
    Ed25519Signer,
    PolicyEngine,
    Verdict,
)

load_dotenv(Path(__file__).resolve().parents[1] / ".env")


def load_rules(handle: str | None) -> ProgramRules:
    if handle and os.environ.get("HACKERONE_API_USERNAME") and os.environ.get("HACKERONE_API_TOKEN"):
        from aegis.ingest import HackerOneClient

        with HackerOneClient.from_env() as client:
            return client.fetch_program_rules(handle)
    sample = json.loads((Path(__file__).with_name("hackerone.sample.json")).read_text())
    return map_program(sample["program"], sample["structured_scopes"]["data"])


def build_engine(rules: ProgramRules) -> tuple[PolicyEngine, list[str]]:
    now = datetime.now(timezone.utc)
    draft = rules.to_authorization_draft(
        customer_id="pilot", authorization_id=f"pilot-{rules.handle}",
        valid_from=(now - timedelta(hours=1)).isoformat(),
        valid_until=(now + timedelta(days=7)).isoformat(),
    )
    conflicts = draft["_meta"]["conflicts"]
    draft.pop("_meta")
    auth = Authorization(**draft)
    signer = Ed25519Signer.generate("pilot-key")
    auth.signature = signer.sign(auth.signing_payload())
    auth.signing_key_id = "pilot-key"
    engine = PolicyEngine(authorization=auth, verifier=signer.verifier(), audit=lambda _d: None)
    return engine, conflicts


def _in_scope_host(entries: list[str]) -> str | None:
    if not entries:
        return None
    first = entries[0]
    return ("preflight." + first[2:]) if first.startswith("*.") else first


def check(label: str, got: Verdict, expected: Verdict) -> bool:
    ok = got == expected
    print(f"  [{'PASS' if ok else 'FAIL'}] {label:44} got={got.value} expected={expected.value}")
    return ok


def main() -> None:
    handle = sys.argv[1] if len(sys.argv) > 1 else None
    rules = load_rules(handle)
    engine, conflicts = build_engine(rules)
    entries = rules.scope_guard_entries()

    print("=" * 74)
    print(f"pre-flight: {rules.platform}:{rules.handle}")
    print("=" * 74)
    print(f"  automation_ok={rules.automation_allowed}  ai_ok={rules.ai_allowed}  "
          f"rate={rules.rate_limit_rps or '(none)'}")
    print(f"  in-scope entries: {entries or '(none)'}")
    for note in rules.notes:
        print(f"    note: {note}")
    if conflicts:
        print("\n  CONFLICTS - resolve before any active run:")
        for c in conflicts:
            print(f"    ! {c}")

    host = _in_scope_host(entries)
    if host is None:
        print("\n  no in-scope web targets; nothing to pre-flight.")
        sys.exit(1)

    print(f"\n  gate checks (no network; sample host {host!r}):")
    results = []
    # If automation is permitted, a passive action in scope must be allowed.
    expect_passive = Verdict.ALLOW if rules.automation_allowed else Verdict.DENY
    results.append(check("in-scope passive_discovery",
                         engine.authorize(ActionRequest(host, "passive_discovery")).verdict, expect_passive))
    results.append(check("out-of-scope passive_discovery",
                         engine.authorize(ActionRequest("not-in-scope.example", "passive_discovery")).verdict,
                         Verdict.DENY))
    results.append(check("prohibited denial_of_service",
                         engine.authorize(ActionRequest(host, "denial_of_service")).verdict, Verdict.DENY))

    ready = all(results) and rules.automation_allowed and not conflicts
    print("\n" + "=" * 74)
    if ready:
        print("READY: gate is enforcing scope; automation permitted. Proceed per PILOT.md.")
    else:
        print("NOT READY: resolve the FAILs / conflicts above before any active testing.")
    print("=" * 74)


if __name__ == "__main__":
    main()
