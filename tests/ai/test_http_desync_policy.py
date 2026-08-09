from __future__ import annotations

from aegis.active import DesyncObservation, analyze_desync_observations
from aegis.ai.active_bridge import followup_intents_for_finding, plan_active_proposals
from aegis.ai.agentic_os import AuthorizationEnvelope, Budget, ProposalPolicy
from aegis.graph import Asset, AssetKind


def test_source_request_smuggling_hint_is_visible_but_not_executable():
    row = {
        "json_answer": {
            "vulnerability_type": "HTTP Request Smuggling",
            "summary": "Possible CL.TE parser disagreement",
            "file_path": "proxy.py",
            "line": 10,
        }
    }
    proposals = followup_intents_for_finding(row)
    desync = next(p for p in proposals if p.metadata["active_detector"] == "http_desync")
    assert desync.requires_network is True
    assert desync.metadata["execution"] == "requires_discovered_route_plan"
    assert "targets" not in desync.metadata

    decision = ProposalPolicy().evaluate(
        desync,
        AuthorizationEnvelope(scope_digest="scope", budget=Budget(max_requests=10)),
    )
    assert decision.approved is False
    assert "network" in decision.reason


def test_evidence_backed_desync_task_still_requires_full_active_authorization():
    asset = Asset(
        engagement_id="eng",
        asset_key="route:POST api.example/submit",
        kind=AssetKind.ROUTE,
        attributes={"method": "POST", "path": "/submit", "host": "api.example"},
    )
    candidates = analyze_desync_observations(
        [
            DesyncObservation(
                route="/submit",
                host="api.example",
                client_protocol="h2",
                upstream_protocol="h1",
                intermediary_chain=("edge", "origin"),
                response_desync_signal=True,
            )
        ]
    )
    plan, proposals = plan_active_proposals(
        [asset],
        enabled={"http_desync"},
        desync_candidates=candidates,
    )
    assert plan.has("http_desync")
    proposal = proposals[0]
    assert proposal.metadata["active_detector"] == "http_desync"
    assert proposal.requires_network is True

    from aegis.ai.agentic_os import mint_execution_grant
    from aegis.policy.signing import HmacSignatureVerifier
    v = HmacSignatureVerifier({"grant": "k"})
    policy = ProposalPolicy(v)
    budget = Budget(max_requests=10)

    # no grant -> blocked (a self-set boolean cannot authorize a live desync probe)
    blocked = policy.evaluate(
        proposal, AuthorizationEnvelope(scope_digest="scope", budget=budget))
    assert blocked.approved is False
    assert not policy.evaluate(
        proposal,
        AuthorizationEnvelope(scope_digest="scope", network_allowed=True, state_change_allowed=True,
                              human_approval=True, budget=budget)).approved

    # only a signed grant granting network + state-change + human approval authorizes it
    grant = mint_execution_grant(type("D", (), {"allowed": True})(), scope_digest="scope",
                                 budget=budget, verifier=v, network=True, state_change=True,
                                 human_approval=True)
    approved = policy.evaluate(
        proposal, AuthorizationEnvelope(scope_digest="scope", budget=budget, grant=grant))
    assert approved.approved is True
