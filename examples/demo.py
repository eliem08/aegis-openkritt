"""Runnable walkthrough of the policy core.

    python examples/demo.py

Loads the sample authorization object, signs it with a demo control-plane key,
builds a PolicyEngine, and runs a series of proposed actions through the single
gate — printing the verdict, tier, reasons, and any incidents for each.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis.policy import (  # noqa: E402
    ActionRequest,
    Authorization,
    HmacSignatureVerifier,
    PolicyEngine,
)

DEMO_KEY_ID = "control-plane-demo"
DEMO_SECRET = "demo-only-secret-do-not-use-in-prod"


def load_signed_authorization(verifier: HmacSignatureVerifier) -> Authorization:
    raw = json.loads((Path(__file__).with_name("authorization.sample.json")).read_text())
    # Refresh the validity window so the demo never runs against an expired grant.
    now = datetime.now(timezone.utc)
    raw["valid_from"] = (now - timedelta(hours=1)).isoformat()
    raw["valid_until"] = (now + timedelta(days=30)).isoformat()
    auth = Authorization(**raw)
    auth.signature = verifier.sign(auth.signing_payload(), DEMO_KEY_ID)
    auth.signing_key_id = DEMO_KEY_ID
    return auth


def show(engine: PolicyEngine, label: str, request: ActionRequest) -> None:
    d = engine.authorize(request)
    tier = d.tier.label if d.tier else "-"
    print(f"\n[{label}]")
    print(f"  action   : {request.action}  ->  target {request.target}")
    print(f"  verdict  : {d.verdict.value.upper()}   (tier: {tier})")
    if d.required_approvals:
        print(f"  approvals: {', '.join(d.required_approvals)}")
    if d.incidents:
        print(f"  INCIDENTS: {', '.join(d.incidents)}")
    for r in d.reasons:
        print(f"    - {r.code.value}: {r.message}")


def main() -> None:
    verifier = HmacSignatureVerifier({DEMO_KEY_ID: DEMO_SECRET})
    auth = load_signed_authorization(verifier)
    engine = PolicyEngine(authorization=auth, verifier=verifier, audit=lambda _d: None)

    print("=" * 72)
    print("aegis policy core - decision walkthrough")
    print("=" * 72)

    show(engine, "passive recon, in scope", ActionRequest("api.example.test", "passive_discovery"))
    show(engine, "authenticated test", ActionRequest("app.example.test", "authenticated_testing"))
    show(engine, "out of scope", ActionRequest("evil.example.com", "passive_discovery"))
    show(engine, "prohibited (DoS)", ActionRequest("api.example.test", "denial_of_service"))
    show(engine, "state-changing proof", ActionRequest("api.example.test", "safe_state_change"))
    show(engine, "sensitive (cross-tenant)", ActionRequest("api.example.test", "cross_tenant_proof"))

    # Now supply the required approvals for the sensitive action.
    pending = engine.authorize(ActionRequest("api.example.test", "cross_tenant_proof"))
    approved = ActionRequest(
        "api.example.test",
        "cross_tenant_proof",
        approvals=frozenset(pending.required_approvals),
    )
    show(engine, "sensitive, with approvals granted", approved)

    # Fire the kill switch — everything halts.
    engine.kill_switch.fire("operator pressed stop")
    show(engine, "after kill switch", ActionRequest("api.example.test", "passive_discovery"))

    print("\n" + "=" * 72)


if __name__ == "__main__":
    main()
