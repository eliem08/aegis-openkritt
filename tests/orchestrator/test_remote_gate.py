"""Drive the orchestrator loop over the control-plane API via RemoteGate.

Uses FastAPI's TestClient as the httpx transport, so requests traverse the full
ASGI stack (correlation middleware, bearer auth, routing) exactly as they would
over a socket — the gate is genuinely remote, just in-process.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from aegis.api import ApiPrincipal, ControlPlaneConfig, Role, create_app
from aegis.model import EngagementInputs, PlannedAction
from aegis.orchestrator import (
    Orchestrator,
    PassiveReconWorker,
    RemoteGate,
    ScriptedWorker,
    StaticPlanner,
    WorkerRegistry,
    WorkerResult,
)
from aegis.policy import Authorization, HmacSignatureVerifier

OP, AGENT = "op-remote-token", "agent-remote-token"
KID, SECRET = "kid-remote", "remote-secret"
INPUTS = EngagementInputs(targets=["api.example.test"])


@pytest.fixture
def client() -> TestClient:
    config = ControlPlaneConfig(
        api_keys={
            OP: ApiPrincipal("operator", Role.OPERATOR),
            AGENT: ApiPrincipal("agent", Role.AGENT),
        },
        signing_keys={KID: SECRET},
    )
    return TestClient(create_app(config))


def _signed_auth(**overrides) -> dict:
    now = datetime.now(timezone.utc)
    base = dict(
        customer_id="c",
        authorization_id=f"auth-{uuid.uuid4().hex[:8]}",
        ownership_proof=["dns-txt"],
        targets=["api.example.test", "app.example.test"],
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=10),
        permitted_actions=["passive_discovery", "authenticated_testing", "cross_tenant_proof"],
        prohibited_actions=["denial_of_service"],
        rate_limits={"requests_per_second": 5, "max_concurrent_sessions": 3},
        approval_required_for=["cross_tenant_proof"],
        spend_budget=100.0,
    )
    base.update(overrides)
    auth = Authorization(**base)
    auth.signature = HmacSignatureVerifier({KID: SECRET}).sign(auth.signing_payload(), KID)
    auth.signing_key_id = KID
    return auth.model_dump(mode="json")


def _register(client: TestClient, **overrides) -> str:
    payload = _signed_auth(**overrides)
    resp = client.post("/engagements", headers={"Authorization": f"Bearer {OP}"}, json=payload)
    assert resp.status_code == 201, resp.text
    return payload["authorization_id"]


def _gate(client: TestClient, engagement_id: str) -> RemoteGate:
    return RemoteGate(client=client, engagement_id=engagement_id, token=AGENT)


def _orch(client, eid, registry, **kw) -> Orchestrator:
    return Orchestrator(
        gate=_gate(client, eid), planner=StaticPlanner(kw.pop("actions")),
        workers=registry, engagement_id=eid, **kw,
    )


def _recon_registry() -> WorkerRegistry:
    reg = WorkerRegistry()
    reg.register(PassiveReconWorker())
    return reg


def test_remote_passive_executes_and_maps_surface(client):
    eid = _register(client)
    actions = [PlannedAction(target="api.example.test", action="passive_discovery", worker="passive_recon")]
    run = _orch(client, eid, _recon_registry(), actions=actions).run(INPUTS)
    assert len(run.executed_action_ids) == 1
    assert run.surface.hosts() == {"api.example.test"}


def test_remote_out_of_scope_blocked(client):
    eid = _register(client)
    actions = [PlannedAction(target="evil.com", action="passive_discovery", worker="passive_recon")]
    run = _orch(client, eid, _recon_registry(), actions=actions).run(INPUTS)
    assert run.executed_action_ids == []
    assert any("target_out_of_scope" in [r["code"] for r in b.decision["reasons"]] for b in run.blocked)


def test_remote_prohibited_blocked(client):
    eid = _register(client)
    actions = [PlannedAction(target="api.example.test", action="denial_of_service", worker="passive_recon")]
    run = _orch(client, eid, _recon_registry(), actions=actions).run(INPUTS)
    assert any("action_prohibited" in [r["code"] for r in b.decision["reasons"]] for b in run.blocked)


def test_remote_finding_flow(client, make_candidate, make_evidence):
    eid = _register(client)
    ev = make_evidence()
    cand = make_candidate(evidence_id=ev.evidence_id)
    reg = _recon_registry()
    reg.register(ScriptedWorker("probe", results={"authenticated_testing": WorkerResult(candidates=[cand], evidence=[ev])}))
    actions = [PlannedAction(target="api.example.test", action="authenticated_testing", worker="probe")]
    run = _orch(client, eid, reg, actions=actions).run(INPUTS)
    assert len(run.executed_action_ids) == 1
    assert len(run.findings) == 1


def test_remote_require_approval_then_grant(client, make_candidate, make_evidence):
    eid = _register(client)
    ev = make_evidence()
    cand = make_candidate(evidence_id=ev.evidence_id)
    reg = _recon_registry()
    reg.register(ScriptedWorker("probe", results={"cross_tenant_proof": WorkerResult(candidates=[cand], evidence=[ev])}))
    actions = [PlannedAction(target="api.example.test", action="cross_tenant_proof", worker="probe")]

    # First run: escalated, nothing executed.
    run1 = _orch(client, eid, reg, actions=actions).run(INPUTS)
    assert run1.executed_action_ids == []
    assert len(run1.escalations) == 1

    # Operator grants approval through the API's ledger.
    g = client.post(
        f"/engagements/{eid}/approvals",
        headers={"Authorization": f"Bearer {OP}"},
        json={"action": "cross_tenant_proof", "target": "api.example.test"},
    )
    assert g.status_code == 201

    # Second run: the server now merges the granted tokens -> allowed.
    run2 = _orch(client, eid, reg, actions=actions).run(INPUTS)
    assert len(run2.executed_action_ids) == 1
    assert len(run2.findings) == 1


def test_remote_kill_switch_halts(client):
    eid = _register(client)
    client.post(
        f"/engagements/{eid}/kill",
        headers={"Authorization": f"Bearer {OP}"},
        json={"reason": "operator stop"},
    )
    actions = [PlannedAction(target="api.example.test", action="passive_discovery", worker="passive_recon")]
    run = _orch(client, eid, _recon_registry(), actions=actions).run(INPUTS)
    assert run.halted is True
    assert "kill switch" in run.halt_reason
    assert run.executed_action_ids == []


def test_remote_commit_debits_budget(client):
    eid = _register(client, rate_limits={"requests_per_second": 1, "max_concurrent_sessions": 3})
    actions = [
        PlannedAction(target="api.example.test", action="passive_discovery", worker="passive_recon"),
        PlannedAction(target="api.example.test", action="passive_discovery", worker="passive_recon"),
    ]
    run = _orch(client, eid, _recon_registry(), actions=actions).run(INPUTS)
    assert len(run.executed_action_ids) == 1
    assert any("rate_budget_exceeded" in [r["code"] for r in b.decision["reasons"]] for b in run.blocked)
