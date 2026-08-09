from __future__ import annotations

from datetime import UTC, datetime, timedelta

from aegis.ai.agentic_os import SecurityKnowledgeGraph
from aegis.ai.jarvis.hunter_phase_a import HunterIntelligencePhaseA
from aegis.ai.jarvis.hunter_techniques import HunterTechnique, technique_definition
from aegis.ai.jarvis.javascript_intelligence import (
    JavaScriptIntelligenceAgent,
    JSDiscoveryKind,
)
from aegis.ai.jarvis.mission_scheduler import TaskState
from aegis.ai.jarvis.recon_intelligence import (
    CertificateIntelligenceAgent,
    CertificateRecord,
    ReconCorrelationAgent,
)
from aegis.ingest.program import AssetType, ProgramRules, ScopeAsset

NOW = datetime(2026, 8, 9, 12, tzinfo=UTC)


def _certificate(fingerprint: str, sans: tuple[str, ...], days: int = 0):
    return CertificateRecord(
        fingerprint=fingerprint,
        sans=sans,
        issuer="Example CA",
        subject=sans[0],
        serial=f"serial-{fingerprint}",
        not_before=NOW + timedelta(days=days),
        not_after=NOW + timedelta(days=90 + days),
        observed_at=NOW + timedelta(days=days),
    )


def test_javascript_and_source_map_intelligence_is_structured_cached_and_provenanced():
    bundle_url = "https://app.example.com/static/app.js"
    map_url = "https://app.example.com/static/app.js.map"
    bundle = """
      const api = 'https://api.example.com/graphql';
      const ws = 'wss://api.example.com/events';
      const client_id = 'public-web-client';
      const redirect_uri = 'https://app.example.com/oauth/callback';
      const featureFlags = { newBilling: true };
      gtag('config', 'G-ABCDEF12');
      //# sourceMappingURL=app.js.map
    """
    source_map = {
        "version": 3,
        "sources": ["src/admin.ts"],
        "sourcesContent": ["const hidden = '/api/admin/import';"],
    }
    agent = JavaScriptIntelligenceAgent()
    first = agent.analyze(
        {bundle_url: bundle}, source_maps={map_url: source_map},
        scope_hosts={"*.example.com"}, observed_at=NOW,
    )
    second = agent.analyze(
        {bundle_url: bundle}, source_maps={map_url: source_map},
        scope_hosts={"*.example.com"}, observed_at=NOW + timedelta(days=1),
    )
    assert first is second
    assert {
        JSDiscoveryKind.GRAPHQL_ENDPOINT,
        JSDiscoveryKind.WEBSOCKET_ENDPOINT,
        JSDiscoveryKind.OAUTH_CLIENT,
        JSDiscoveryKind.REDIRECT_URI,
        JSDiscoveryKind.FEATURE_FLAG,
        JSDiscoveryKind.PUBLIC_TRACKING_ID,
        JSDiscoveryKind.SOURCE_MAP,
        JSDiscoveryKind.SOURCE_MODULE,
        JSDiscoveryKind.API_ENDPOINT,
    } <= {item.kind for item in first}
    hidden = next(item for item in first if item.value == "/api/admin/import")
    assert hidden.technique is HunterTechnique.JS_SOURCE_MAP_RECOVERY
    assert hidden.metadata["original_filename"] == "src/admin.ts"
    assert hidden.evidence_digest and hidden.line == 1

    graph = SecurityKnowledgeGraph()
    agent.persist(first, graph)
    assert graph.nodes[hidden.discovery_id]["kind"] == "api_endpoint"
    assert any(edge.target == hidden.discovery_id and edge.relation == "reveals"
               for edge in graph.edges)


def test_certificate_intelligence_tracks_temporal_change_and_reuse():
    previous = (_certificate("old", ("app.example.com",)),)
    current = (_certificate("new", ("app.example.com", "api.example.com"), 30),)
    signals = CertificateIntelligenceAgent().analyze(current, previous=previous)
    kinds = {item.kind for item in signals}
    assert {"new_san", "shared_certificate"} <= kinds
    new_san = next(item for item in signals if item.kind == "new_san")
    assert new_san.hostname == "api.example.com"
    assert any(item.startswith("fingerprint:") for item in new_san.evidence)
    assert new_san.observed_at == NOW + timedelta(days=30)


def test_public_tracking_correlation_is_not_scope_authorization():
    agent = JavaScriptIntelligenceAgent()
    observations = agent.analyze(
        {
            "https://app.example.com/a.js": "gtag('config','G-SHARED123');",
            "https://sibling.invalid/b.js": "gtag('config','G-SHARED123');",
        },
        scope_hosts={"*.example.com"}, observed_at=NOW,
    )
    correlations = ReconCorrelationAgent().correlate(
        javascript=observations, authorized_hosts={"*.example.com"}
    )
    item = next(correlation for correlation in correlations
                if correlation.relationship_type == "shares_public_tracking_id")
    assert item.target_asset == "sibling.invalid"
    assert item.target_authorized is False
    assert "not ownership proof" in item.reasoning_summary
    assert item.evidence


def test_phase_a_end_to_end_compiles_scope_safe_profit_ranked_missions():
    program = ProgramRules(
        handle="hunter-lab",
        in_scope=[ScopeAsset(
            identifier="https://*.example.com", asset_type=AssetType.WILDCARD,
            eligible_for_submission=True, eligible_for_bounty=True,
        )],
    )
    graph = SecurityKnowledgeGraph()
    pipeline = HunterIntelligencePhaseA()
    result = pipeline.run(
        program=program,
        scope_digest="scope:hunter-lab",
        authorization_id="auth:hunter-lab",
        graph=graph,
        bundles={
            "https://app.example.com/app.js": (
                "const gql='https://api.example.com/graphql';"
                "gtag('config','G-SHARED123');//# sourceMappingURL=app.js.map"
            ),
            "https://outside.invalid/app.js": "gtag('config','G-SHARED123');",
        },
        source_maps={
            "https://app.example.com/app.js.map": {
                "version": 3,
                "sources": ["src/client.ts"],
                "sourcesContent": ["const route='/api/v2/import';"],
            }
        },
        certificates=(
            _certificate("cert-new", ("app.example.com", "legacy.invalid")),
        ),
        capacity=50,
        exploration_fraction=1.0,
    )
    assert result.javascript and result.correlations and result.opportunities
    assert result.selected and len(result.missions) == len(result.selected)
    assert all(item.estimated_payout_usd is None for item in result.opportunities)

    authorized = next(item for item in result.opportunities
                      if item.asset_locator == "https://api.example.com/graphql")
    authorized_mission = next(mission for mission in result.missions
                              if mission.opportunity_id == authorized.opportunity_id)
    assert authorized.prerequisite_state == "ready"
    assert authorized_mission.tasks[0].state is TaskState.PENDING
    assert authorized_mission.tasks[0].executor_capability == (
        "jarvis:research:javascript_route_recovery"
    )

    inferred = next(item for item in result.opportunities
                    if item.asset_locator == "outside.invalid")
    inferred_mission = next(mission for mission in result.missions
                            if mission.opportunity_id == inferred.opportunity_id)
    assert inferred.prerequisite_state == "scope_confirmation_required"
    assert {task.state for task in inferred_mission.tasks} == {
        TaskState.WAITING_FOR_PREREQUISITE
    }
    assert graph.nodes["asset:domain:outside.invalid"]["authorized"] is False


def test_phase_a_techniques_declare_runtime_contracts():
    for technique in HunterTechnique:
        definition = technique_definition(technique)
        assert definition.required_observations
        assert definition.compatible_asset_types
        assert definition.worker_capability
        assert definition.evidence_requirements
