from decimal import Decimal
import json
import pytest
from aegis.nextgen import (
    AttackSurfaceGraph, CapturedResponse, EdgeKind, EventBus, EventType,
    EvidenceArtifact, EvidenceBundleWriter, FindingLifecycle, ReproductionState,
    SecurityEvent, WorkOpportunity, authorization_differential, rank_opportunities,
)


def event(kind, asset, payload=None, source="test"):
    return SecurityEvent(type=kind, scope_id="scope", engagement_id="eng",
                         source_module=source, asset_key=asset, payload=payload or {})


def test_recursive_graph_profit_and_evidence(tmp_path):
    bus = EventBus(scope_id="scope", engagement_id="eng")
    bus.subscribe(EventType.DOMAIN, "subdomain", lambda parent: [event(
        EventType.SUBDOMAIN, "subdomain:api.example.com",
        {"parent_asset_keys": [parent.asset_key], "relation": "contains"}, "subdomain")])
    graph = AttackSurfaceGraph()
    for row in bus.publish(event(EventType.DOMAIN, "domain:example.com")):
        graph.ingest(row)
    assert graph.neighbors("domain:example.com", EdgeKind.CONTAINS)[0].key.endswith("api.example.com")

    scores = rank_opportunities([
        WorkOpportunity("fresh", Decimal("1000"), .6, .5, duplicate_risk=.1,
                        information_gain=.2, model_cost=Decimal("5")),
        WorkOpportunity("crowded", Decimal("1000"), .6, .5, duplicate_risk=.95,
                        review_cost=Decimal("50")),
    ])
    assert scores[0].opportunity_id == "fresh" and scores[0].profitable

    result = authorization_differential(
        CapturedResponse("a", 200, {"v": "CANARY"}),
        CapturedResponse("b", 200, {"v": "CANARY"}),
        CapturedResponse("b", 404, {}), canary="CANARY")
    assert result.passed

    bundle = EvidenceBundleWriter(tmp_path, "f", "abc", "scope").write([
        EvidenceArtifact("request.http", "Authorization: Bearer secret")])
    assert "secret" not in (bundle / "request.http").read_text()
    assert json.loads((bundle / "manifest.json").read_text())["bundle_sha256"]


def test_lifecycle_blocks_agent_self_approval():
    lifecycle = FindingLifecycle(finding_id="f", state=ReproductionState.INDEPENDENTLY_VERIFIED)
    with pytest.raises(PermissionError):
        lifecycle.transition(ReproductionState.HUMAN_APPROVED, actor="agent:review", reason="approve")
