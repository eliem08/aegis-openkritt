import pytest

from aegis.ai.agentic_os import SecurityKnowledgeGraph
from aegis.ai.jarvis.cross_surface_intelligence import (
    CrossSurfaceIntelligenceAgent,
    CrossSurfaceKind,
    CrossSurfaceObservation,
    CrossSurfaceOutcome,
)
from aegis.ai.jarvis.hunter_phase_g import HunterIntelligencePhaseG
from aegis.ai.jarvis.mission_scheduler import TaskState
from aegis.ingest.program import ProgramRules


def _observation(kind=CrossSurfaceKind.GRAPHQL, **overrides):
    values = dict(
        observation_id=f"obs-{kind.value}", kind=kind,
        source="mobile://callsite" if kind is CrossSurfaceKind.MOBILE_BACKEND else "/source",
        target="https://api.example.test/operation", operation="readInvoice",
        authorized_source=True, authorized_target=True, controlled_identities=True,
        control_succeeded=True, probe_succeeded=True,
        protected_marker_in_probe=True, synthetic_fixture=True,
        evidence=("capture:control", "capture:probe", "canary:invoice"),
    )
    values.update(overrides)
    return CrossSurfaceObservation(**values)


@pytest.mark.parametrize("kind", [
    CrossSurfaceKind.UPLOAD, CrossSurfaceKind.GRAPHQL, CrossSurfaceKind.WEBSOCKET,
    CrossSurfaceKind.GRPC, CrossSurfaceKind.DEEP_LINK,
])
def test_cross_surface_active_oracles_require_protected_effect(kind):
    verdict = CrossSurfaceIntelligenceAgent().evaluate(_observation(kind))
    assert verdict.outcome is CrossSurfaceOutcome.VIOLATION
    negative = CrossSurfaceIntelligenceAgent().evaluate(_observation(
        kind, probe_succeeded=False, protected_marker_in_probe=False,
        protected_state_changed=False,
    ))
    assert negative.outcome is CrossSurfaceOutcome.CONSISTENT


def test_mobile_backend_correlation_is_offline_and_requires_evidence_and_scope():
    verdict = CrossSurfaceIntelligenceAgent().evaluate(_observation(
        CrossSurfaceKind.MOBILE_BACKEND, controlled_identities=False,
        synthetic_fixture=False, probe_succeeded=False,
        protected_marker_in_probe=False,
    ))
    assert verdict.outcome is CrossSurfaceOutcome.CORRELATION
    inferred = CrossSurfaceIntelligenceAgent().evaluate(_observation(
        CrossSurfaceKind.MOBILE_BACKEND, authorized_target=False,
    ))
    assert inferred.outcome is CrossSurfaceOutcome.INCONCLUSIVE


def test_deep_link_sensitive_state_requires_user_confirmation():
    verdict = CrossSurfaceIntelligenceAgent().evaluate(_observation(
        CrossSurfaceKind.DEEP_LINK, protected_marker_in_probe=False,
        protected_state_changed=True, user_confirmation_observed=False,
    ))
    assert verdict.outcome is CrossSurfaceOutcome.VIOLATION


def test_cross_surface_fails_closed_without_controlled_fixture_or_baseline():
    agent = CrossSurfaceIntelligenceAgent()
    assert agent.evaluate(_observation(
        controlled_identities=False
    )).outcome is CrossSurfaceOutcome.INCONCLUSIVE
    assert agent.evaluate(_observation(
        control_succeeded=False
    )).outcome is CrossSurfaceOutcome.INCONCLUSIVE


def test_phase_g_compiles_each_surface_through_canonical_runtime():
    observations = tuple(_observation(kind) for kind in CrossSurfaceKind)
    graph = SecurityKnowledgeGraph()
    result = HunterIntelligencePhaseG().run(
        program=ProgramRules(handle="surface-lab"), scope_digest="scope:surface",
        authorization_id="auth:surface", asset_locator="https://api.example.test",
        asset_authorized=True, graph=graph, observations=observations,
        capacity=20, exploration_fraction=1.0,
    )
    assert len(result.opportunities) == len(CrossSurfaceKind)
    assert all(row.estimated_payout_usd is None for row in result.opportunities)
    techniques = {row.metadata["technique"] for row in result.opportunities}
    assert {"upload_workflow_differential", "mobile_backend_correlation",
            "graphql_authorization_differential", "websocket_state_differential",
            "grpc_authorization_differential", "deep_link_trust_differential"} == techniques
    mobile = next(row for row in result.opportunities
                  if row.metadata["technique"] == "mobile_backend_correlation")
    mission = next(row for row in result.missions if row.opportunity_id == mobile.opportunity_id)
    assert mission.tasks[0].executor_capability == (
        "jarvis:research:mobile-backend-correlation"
    )
    assert mission.tasks[0].expected_requests == 0
    assert graph.nodes[mobile.opportunity_id]["kind"] == "hunt_opportunity"


def test_phase_g_missing_backend_and_inferred_asset_wait_fail_closed():
    result = HunterIntelligencePhaseG().run(
        program=ProgramRules(handle="surface-lab"), scope_digest="scope:surface",
        authorization_id="auth:surface", asset_locator="https://inferred.invalid",
        asset_authorized=False, graph=SecurityKnowledgeGraph(), backend_available=False,
        capacity=10, exploration_fraction=1.0,
    )
    assert result.opportunities[0].prerequisite_state == "scope_confirmation_required"
    assert all(task.state is TaskState.WAITING_FOR_PREREQUISITE
               for task in result.missions[0].tasks)
