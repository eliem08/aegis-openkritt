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

    policy = ProposalPolicy()
    blocked = policy.evaluate(
        proposal,
        AuthorizationEnvelope(scope_digest="scope", budget=Budget(max_requests=10)),
    )
    assert blocked.approved is False

    approved = policy.evaluate(
        proposal,
        AuthorizationEnvelope(
            scope_digest="scope",
            network_allowed=True,
            state_change_allowed=True,
            human_approval=True,
            budget=Budget(max_requests=10),
        ),
    )
    assert approved.approved is True
