from aegis.ai.agentic_os import SecurityKnowledgeGraph
from aegis.ai.jarvis.cache_intelligence import (
    CacheArchitectureAgent,
    CacheExperiment,
    CacheObservation,
    CacheOutcome,
)
from aegis.ai.jarvis.hunter_phase_d import HunterIntelligencePhaseD
from aegis.ai.jarvis.mission_scheduler import TaskState
from aegis.ingest.program import ProgramRules


def _observation(request_id, client, markers=(), *, path="/account", authenticated=False,
                 evidence=(), headers=None, digest="body"):
    return CacheObservation(
        request_id, client, path, 200, digest, markers,
        headers or {"CF-Cache-Status": "HIT", "Age": "10"},
        authenticated, evidence,
    )


def _experiment(*, victim_markers=("marker-1",), negative_markers=(), authorized=True,
                private=False):
    return CacheExperiment(
        "experiment-1", "x-forwarded-host", "marker-1",
        _observation("prime", "client-a", ("marker-1",), evidence=("capture:prime",)),
        _observation("victim", "client-b", victim_markers, evidence=("capture:victim",)),
        _observation("negative", "client-c", negative_markers,
                     evidence=("capture:negative",)),
        authorized, private,
    )


def test_cache_key_oracle_requires_cross_client_marker_negative_control_and_cache_signal():
    verdict = CacheArchitectureAgent().evaluate(_experiment())
    assert verdict.outcome is CacheOutcome.SHARED_INFLUENCE_CONFIRMED
    assert verdict.confidence == 0.97
    assert {"cdn", "shared-cache"} <= set(verdict.topology)

    clean = CacheArchitectureAgent().evaluate(_experiment(victim_markers=()))
    assert clean.outcome is CacheOutcome.CONSISTENT

    no_negative = _experiment(negative_markers=("marker-1",))
    assert CacheArchitectureAgent().evaluate(no_negative).outcome is CacheOutcome.INCONCLUSIVE


def test_private_marker_cross_client_is_distinct_high_value_outcome():
    verdict = CacheArchitectureAgent().evaluate(_experiment(private=True))
    assert verdict.outcome is CacheOutcome.PRIVATE_DATA_SHARED


def test_cache_oracle_fails_closed_without_authorization_or_distinct_client():
    assert CacheArchitectureAgent().evaluate(
        _experiment(authorized=False)
    ).outcome is CacheOutcome.INCONCLUSIVE
    experiment = _experiment()
    same_client = CacheExperiment(
        experiment.experiment_id, experiment.dimension, experiment.marker,
        experiment.prime,
        _observation("victim", "client-a", ("marker-1",)),
        experiment.negative_control, True,
    )
    assert CacheArchitectureAgent().evaluate(same_client).outcome is CacheOutcome.INCONCLUSIVE


def test_deception_requires_authenticated_same_content_static_suffix_and_cache_signal():
    canonical = _observation("canonical", "client-a", path="/account", authenticated=True,
                             evidence=("capture:canonical",), digest="private-body")
    variant = _observation("variant", "client-a", path="/account/profile.css",
                           evidence=("capture:variant",), digest="private-body")
    outcome, _ = CacheArchitectureAgent.deception_hypothesis(canonical, variant)
    assert outcome is CacheOutcome.HYPOTHESIS
    changed = _observation("changed", "client-a", path="/account/profile.css",
                           digest="different")
    assert CacheArchitectureAgent.deception_hypothesis(canonical, changed)[0] is (
        CacheOutcome.CONSISTENT
    )


def test_phase_d_compiles_private_shared_cache_verdict_into_canonical_mission():
    graph = SecurityKnowledgeGraph()
    result = HunterIntelligencePhaseD().run(
        program=ProgramRules(handle="cache-lab"), scope_digest="scope:cache",
        authorization_id="auth:cache", asset_locator="https://app.example.test",
        asset_authorized=True, graph=graph, experiments=(_experiment(private=True),),
        capacity=10, exploration_fraction=1.0,
    )
    assert result.verdicts[0].outcome is CacheOutcome.PRIVATE_DATA_SHARED
    opportunity = result.opportunities[0]
    assert opportunity.estimated_payout_usd is None
    assert opportunity.metadata["technique"] == "cache_private_shared"
    mission = result.missions[0]
    assert mission.tasks[0].executor_capability == (
        "dynamic:private-shared-cache-differential"
    )
    assert mission.tasks[0].expected_requests == 3
    assert mission.tasks[0].state is TaskState.PENDING
    assert graph.nodes[opportunity.opportunity_id]["kind"] == "hunt_opportunity"


def test_phase_d_missing_backend_and_inferred_asset_wait_fail_closed():
    result = HunterIntelligencePhaseD().run(
        program=ProgramRules(handle="cache-lab"), scope_digest="scope:cache",
        authorization_id="auth:cache", asset_locator="https://inferred.invalid",
        asset_authorized=False, graph=SecurityKnowledgeGraph(), backend_available=False,
        capacity=10, exploration_fraction=1.0,
    )
    assert result.opportunities[0].prerequisite_state == "scope_confirmation_required"
    assert all(task.state is TaskState.WAITING_FOR_PREREQUISITE
               for task in result.missions[0].tasks)
