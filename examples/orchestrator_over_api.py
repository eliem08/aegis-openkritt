"""Drive the orchestrator loop over the control-plane API on a real socket.

    python examples/orchestrator_over_api.py

Boots the control plane with uvicorn in a background thread, then runs the
orchestrator from the "agent side" against it via RemoteGate: workers execute
locally, every policy decision is an HTTP call to the control plane. Shows the
approval round-trip (escalate -> operator grants via API -> re-run allowed).
"""

from __future__ import annotations

import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import httpx  # noqa: E402
import uvicorn  # noqa: E402

from aegis.api import ApiPrincipal, ControlPlaneConfig, Role, create_app  # noqa: E402
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
    RemoteGate,
    ScriptedWorker,
    StaticPlanner,
    WorkerRegistry,
    WorkerResult,
)
from aegis.policy import Authorization, HmacSignatureVerifier  # noqa: E402

OP, AGENT = "op-token", "agent-token"
KID, SECRET = "kid-1", "control-plane-secret"
PORT = 8231
BASE = f"http://127.0.0.1:{PORT}"
EID = "auth-2026-001"


def start_control_plane() -> uvicorn.Server:
    config = ControlPlaneConfig(
        api_keys={OP: ApiPrincipal("operator", Role.OPERATOR), AGENT: ApiPrincipal("agent", Role.AGENT)},
        signing_keys={KID: SECRET},
    )
    server = uvicorn.Server(uvicorn.Config(create_app(config), host="127.0.0.1", port=PORT, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    return server


def signed_auth() -> dict:
    now = datetime.now(timezone.utc)
    auth = Authorization(
        customer_id="customer-123", authorization_id=EID, ownership_proof=["dns-txt", "signed-roe"],
        targets=["api.example.test"], valid_from=now - timedelta(days=1), valid_until=now + timedelta(days=30),
        permitted_actions=["passive_discovery", "authenticated_testing", "cross_tenant_proof"],
        prohibited_actions=["denial_of_service"],
        rate_limits={"requests_per_second": 5, "max_concurrent_sessions": 3},
        approval_required_for=["cross_tenant_proof"], spend_budget=250.0,
    )
    auth.signature = HmacSignatureVerifier({KID: SECRET}).sign(auth.signing_payload(), KID)
    auth.signing_key_id = KID
    return auth.model_dump(mode="json")


def build_registry() -> WorkerRegistry:
    reg = WorkerRegistry()
    reg.register(PassiveReconWorker())
    bola_ev = EvidenceBundle(
        steps=[InteractionStep(summary="GET /users/1001 as user_a -> seeded record CANARY-7f3")],
        canary=Canary(kind=CanaryKind.SEEDED_RECORD, value="CANARY-7f3"),
        observed="cross-object read", expected="403", confidence=0.85,
    )
    bola = Candidate(asset="api.example.test", route="/users/{id}", parameter="id", cwe="CWE-639",
                     action="authenticated_testing", confidence=0.85, evidence_id=bola_ev.evidence_id,
                     p_exploit=0.8, business_impact=0.9, asset_criticality=0.9)
    xt_ev = EvidenceBundle(
        steps=[InteractionStep(summary="tenant_b reads tenant_a via /export")],
        canary=Canary(kind=CanaryKind.SEEDED_RECORD, value="CANARY-x9"), confidence=0.8,
    )
    xt = Candidate(asset="api.example.test", route="/export", parameter="tenant", cwe="CWE-284",
                   action="cross_tenant_proof", confidence=0.8, evidence_id=xt_ev.evidence_id,
                   p_exploit=0.7, business_impact=0.9, asset_criticality=0.9)
    reg.register(ScriptedWorker("probe", results={
        "authenticated_testing": WorkerResult(candidates=[bola], evidence=[bola_ev]),
        "cross_tenant_proof": WorkerResult(candidates=[xt], evidence=[xt_ev]),
    }))
    return reg


PLAN = [
    PlannedAction(target="api.example.test", action="passive_discovery", worker="passive_recon"),
    PlannedAction(target="api.example.test", action="authenticated_testing", worker="probe"),
    PlannedAction(target="api.example.test", action="cross_tenant_proof", worker="probe"),
    PlannedAction(target="api.example.test", action="denial_of_service", worker="probe"),
]


def main() -> None:
    server = start_control_plane()
    op = {"Authorization": f"Bearer {OP}"}
    print("=" * 76)
    print("orchestrator driving the control plane over HTTP  ({})".format(BASE))
    print("=" * 76)

    with httpx.Client(base_url=BASE, timeout=5) as c:
        print("operator registers a signed authorization ->",
              c.post("/engagements", headers=op, json=signed_auth()).status_code)

    gate = RemoteGate(base_url=BASE, engagement_id=EID, token=AGENT)
    orch = Orchestrator(gate=gate, planner=StaticPlanner(PLAN), workers=build_registry(), engagement_id=EID)
    run = orch.run(EngagementInputs(targets=["api.example.test"]))

    print("\nrun summary:", run.summary())
    for f in run.findings:
        print(f"  finding  [{f.ssvc.value.upper()}] {f.cwe} {f.route}  prio={f.priority:.3f}")
    for e in run.escalations:
        print(f"  escalate {e.reason.value}: {e.action.action if e.action else ''} needs={e.required_approvals}")
    for b in run.blocked:
        print(f"  blocked  {b.action.action}: {[r['code'] for r in b.decision.get('reasons', [])]}")

    print("\noperator grants approval for the cross-tenant proof via the API...")
    with httpx.Client(base_url=BASE, timeout=5) as c:
        c.post(f"/engagements/{EID}/approvals", headers=op,
               json={"action": "cross_tenant_proof", "target": "api.example.test"})

    orch2 = Orchestrator(gate=RemoteGate(base_url=BASE, engagement_id=EID, token=AGENT),
                         planner=StaticPlanner([PLAN[2]]), workers=build_registry(), engagement_id=EID)
    run2 = orch2.run(EngagementInputs(targets=["api.example.test"]))
    print("  re-run cross-tenant proof -> executed:",
          bool(run2.executed_action_ids), "| findings:", len(run2.findings))

    gate.close()
    server.should_exit = True
    time.sleep(0.3)
    print("=" * 76)


if __name__ == "__main__":
    main()
