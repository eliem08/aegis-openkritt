"""Runnable walkthrough of the orchestrator loop.

    python examples/orchestrator_demo.py

Builds a signed authorization + policy engine, registers a mock recon worker and
a scripted probe worker, then runs a plan that mixes: safe recon, a real
reproducible finding, a hypothesis (no canary), an approval-gated sensitive
action, an out-of-scope target, and a prohibited action. Prints how the loop
gated each one.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis.model import (  # noqa: E402
    Candidate,
    Canary,
    CanaryKind,
    EngagementInputs,
    EvidenceBundle,
    InteractionStep,
    PlannedAction,
)
from aegis.orchestrator import (  # noqa: E402
    Orchestrator,
    PassiveReconWorker,
    ScriptedWorker,
    StaticPlanner,
    WorkerRegistry,
    WorkerResult,
)
from aegis.policy import Authorization, HmacSignatureVerifier, PolicyEngine  # noqa: E402

KID, SECRET = "demo-kid", "demo-secret"


def build_engine() -> PolicyEngine:
    now = datetime.now(timezone.utc)
    auth = Authorization(
        customer_id="customer-123",
        authorization_id="auth-2026-001",
        ownership_proof=["dns-txt", "signed-roe"],
        targets=["api.example.test"],
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=30),
        permitted_actions=["passive_discovery", "authenticated_testing", "cross_tenant_proof"],
        prohibited_actions=["denial_of_service", "persistence"],
        rate_limits={"requests_per_second": 5, "max_concurrent_sessions": 3},
        approval_required_for=["cross_tenant_proof"],
        escalation_contacts=["secops@example.test"],
        spend_budget=250.0,
    )
    v = HmacSignatureVerifier({KID: SECRET})
    auth.signature = v.sign(auth.signing_payload(), KID)
    auth.signing_key_id = KID
    return PolicyEngine(authorization=auth, verifier=v, audit=lambda _d: None)


def build_registry() -> WorkerRegistry:
    reg = WorkerRegistry()
    reg.register(PassiveReconWorker())

    bola_ev = EvidenceBundle(
        steps=[
            InteractionStep(summary="GET /users/1001 as user_a -> 200 with seeded record"),
            InteractionStep(summary="canary field CANARY-7f3 present in response"),
        ],
        canary=Canary(kind=CanaryKind.SEEDED_RECORD, value="CANARY-7f3"),
        observed="user_a read another tenant's seeded record",
        expected="403 Forbidden",
        code_location="app/api/users.py:get_user",
        replay_ref="replay://eng/auth-2026-001/bola-1",
        confidence=0.85,
    )
    bola = Candidate(
        asset="api.example.test", route="/users/{id}", parameter="id",
        action="authenticated_testing", worker="probe",
        observed="IDOR: cross-object read", expected="403", impact="tenant data exposure",
        cwe="CWE-639", confidence=0.85, evidence_id=bola_ev.evidence_id,
        p_exploit=0.8, business_impact=0.9, asset_criticality=0.9,
    )
    hypothesis = Candidate(
        asset="api.example.test", route="/search", parameter="q",
        action="authenticated_testing", worker="probe",
        observed="reflected value, unconfirmed", cwe="CWE-79", confidence=0.3,
    )  # no evidence -> stays a hypothesis

    xt_ev = EvidenceBundle(
        steps=[InteractionStep(summary="tenant_b token reads tenant_a object via /export")],
        canary=Canary(kind=CanaryKind.SEEDED_RECORD, value="CANARY-x9"),
        observed="cross-tenant export", expected="scoped to tenant", confidence=0.8,
    )
    xt = Candidate(
        asset="api.example.test", route="/export", parameter="tenant",
        action="cross_tenant_proof", worker="probe", cwe="CWE-284",
        confidence=0.8, evidence_id=xt_ev.evidence_id,
        p_exploit=0.7, business_impact=0.9, asset_criticality=0.9,
    )

    reg.register(
        ScriptedWorker(
            "probe",
            results={
                "authenticated_testing": WorkerResult(candidates=[bola, hypothesis], evidence=[bola_ev]),
                "cross_tenant_proof": WorkerResult(candidates=[xt], evidence=[xt_ev]),
            },
        )
    )
    return reg


PLAN = [
    PlannedAction(target="api.example.test", action="passive_discovery", worker="passive_recon", rationale="map surface"),
    PlannedAction(target="api.example.test", action="authenticated_testing", worker="probe", rationale="BOLA probe"),
    PlannedAction(target="api.example.test", action="cross_tenant_proof", worker="probe", rationale="cross-tenant proof"),
    PlannedAction(target="evil.example.com", action="passive_discovery", worker="passive_recon", rationale="oops, out of scope"),
    PlannedAction(target="api.example.test", action="denial_of_service", worker="probe", rationale="never"),
]


def print_run(run) -> None:
    print("\nsummary:", run.summary())
    print("stages :", " -> ".join(run.stages))
    print(f"surface: {sorted(run.surface.hosts())}  ({run.surface.route_count} routes)")

    print("\nFINDINGS (reproducible, deduped, prioritised):")
    for f in run.findings:
        print(f"  [{f.ssvc.value.upper():6}] {f.cwe:8} {f.route:14} status={f.status.value:9} "
              f"prio={f.priority:.3f}  proof={f.exploit_proof_ref}")
    print("\nHYPOTHESES (no reproducible proof -> not reported as findings):")
    for h in run.hypotheses:
        print(f"  - {h.cwe:8} {h.route:14} confidence={h.confidence}")
    print("\nESCALATIONS (human-in-the-loop):")
    for e in run.escalations:
        extra = f" needs={e.required_approvals}" if e.required_approvals else ""
        print(f"  - {e.reason.value}: {e.action.action if e.action else ''}{extra}")
    print("\nBLOCKED (denied by policy):")
    for b in run.blocked:
        codes = [r["code"] for r in b.decision.get("reasons", [])] or [b.decision.get("error")]
        print(f"  - {b.action.action:18} {codes}")


def main() -> None:
    print("=" * 76)
    print("aegis orchestrator - engagement walkthrough")
    print("=" * 76)

    engine = build_engine()
    registry = build_registry()
    orch = Orchestrator(
        engine=engine, planner=StaticPlanner(PLAN), workers=registry,
        engagement_id="auth-2026-001", escalation_contacts=["secops@example.test"],
    )
    run = orch.run(EngagementInputs(targets=["api.example.test"]))
    print_run(run)

    print("\n" + "-" * 76)
    print("operator grants approval for the cross-tenant proof; re-run that action:")
    engine2 = build_engine()
    orch2 = Orchestrator(
        engine=engine2, planner=StaticPlanner([PLAN[2]]), workers=build_registry(),
        engagement_id="auth-2026-001",
        approvals={("cross_tenant_proof", "api.example.test"): {"cross_tenant_proof", "tier:SENSITIVE"}},
    )
    run2 = orch2.run(EngagementInputs(targets=["api.example.test"]))
    print("  executed:", run2.executed_action_ids and "yes" or "no",
          "| findings:", len(run2.findings))
    print("=" * 76)


if __name__ == "__main__":
    main()
