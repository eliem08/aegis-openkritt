from aegis.ai.agentic_os import (
    AuthorizationEnvelope,
    Budget,
    SecurityKnowledgeGraph,
    mint_execution_grant,
    process_grant_verifier,
)
from aegis.ai.jarvis.hunter_phase_e import HunterIntelligencePhaseE
from aegis.ai.jarvis.mission_scheduler import TaskState
from aegis.ai.jarvis.race_intelligence import (
    AttemptResult,
    BoundedConcurrencyHarness,
    RaceConditionAgent,
    RaceExperiment,
    RaceOutcome,
    retry_experiment,
)
from aegis.ingest.program import ProgramRules


def _experiment(*, effects=("charge-1", "charge-2"), key="", synchronized=True):
    return RaceExperiment(
        "race-1",
        tuple(AttemptResult(f"attempt-{index}", 200, (effect,), "state-2",
                            evidence=(f"capture:{index}",))
              for index, effect in enumerate(effects)),
        "state-1", "state-2", 1, key, True, synchronized,
    )


def _grant(*, state_change=True):
    verifier = process_grant_verifier()
    budget = Budget(max_cost_usd=1, max_requests=4, max_human_minutes=1)
    grant = mint_execution_grant(
        type("AllowedPolicyDecision", (), {"allowed": True})(),
        scope_digest="scope:race", budget=budget, verifier=verifier,
        network=True, state_change=state_change, human_approval=True,
    )
    return verifier, AuthorizationEnvelope(
        scope_digest="scope:race", budget=budget, grant=grant
    )


def test_race_agent_detects_double_execution_and_idempotency_failure():
    race = RaceConditionAgent().evaluate(_experiment())
    assert race.outcome is RaceOutcome.DOUBLE_EXECUTION
    idempotency = RaceConditionAgent().evaluate(_experiment(key="sha256:key"))
    assert idempotency.outcome is RaceOutcome.IDEMPOTENCY_FAILURE
    assert idempotency.confidence == 0.98


def test_retry_after_timeout_detects_duplicated_persistent_effect():
    experiment = retry_experiment(
        "retry-1", AttemptResult("first", 504, ("charge-1",), timed_out=True),
        AttemptResult("retry", 200, ("charge-2",)),
        before_state_digest="state-1", after_state_digest="state-3",
    )
    assert RaceConditionAgent().evaluate(experiment).outcome is (
        RaceOutcome.RETRY_DUPLICATED_EFFECT
    )


def test_race_agent_requires_synchronization_synthetic_fixture_and_readback():
    assert RaceConditionAgent().evaluate(
        _experiment(synchronized=False)
    ).outcome is RaceOutcome.INCONCLUSIVE
    missing = RaceExperiment("missing", _experiment().results, "", "", 1, "", True, True)
    assert RaceConditionAgent().evaluate(missing).outcome is RaceOutcome.INCONCLUSIVE


def test_bounded_concurrency_harness_requires_signed_state_grant_and_synchronizes():
    verifier, authorization = _grant()
    harness = BoundedConcurrencyHarness(grant_verifier=verifier, max_concurrency=4)
    results = harness.run(
        attempts=2,
        operation=lambda index: AttemptResult(f"attempt-{index}", 200, (f"effect-{index}",)),
        authorization=authorization,
    )
    assert {row.attempt_id for row in results} == {"attempt-0", "attempt-1"}

    _, weak = _grant(state_change=False)
    try:
        harness.run(
            attempts=2, operation=lambda index: AttemptResult(str(index), 200),
            authorization=weak,
        )
    except PermissionError:
        pass
    else:
        raise AssertionError("underpowered grant executed the race harness")


def test_harness_enforces_request_and_concurrency_bounds():
    verifier, authorization = _grant()
    harness = BoundedConcurrencyHarness(grant_verifier=verifier, max_concurrency=4)
    for attempts in (1, 5):
        try:
            harness.run(
                attempts=attempts, operation=lambda index: AttemptResult(str(index), 200),
                authorization=authorization,
            )
        except PermissionError:
            pass
        else:
            raise AssertionError("out-of-bounds concurrency executed")


def test_phase_e_compiles_race_verdict_into_canonical_mission():
    graph = SecurityKnowledgeGraph()
    result = HunterIntelligencePhaseE().run(
        program=ProgramRules(handle="race-lab"), scope_digest="scope:race",
        authorization_id="auth:race", asset_locator="https://api.example.test",
        asset_authorized=True, graph=graph, experiments=(_experiment(),),
        capacity=10, exploration_fraction=1.0,
    )
    assert result.verdicts[0].outcome is RaceOutcome.DOUBLE_EXECUTION
    opportunity = result.opportunities[0]
    assert opportunity.estimated_payout_usd is None
    assert opportunity.metadata["technique"] == "race_synchronized_differential"
    mission = result.missions[0]
    assert mission.tasks[0].executor_capability == "dynamic:bounded-race-harness"
    assert mission.tasks[0].expected_requests == 4
    assert mission.tasks[0].state is TaskState.PENDING
    assert graph.nodes[opportunity.opportunity_id]["kind"] == "hunt_opportunity"


def test_phase_e_missing_backend_and_inferred_asset_wait_fail_closed():
    result = HunterIntelligencePhaseE().run(
        program=ProgramRules(handle="race-lab"), scope_digest="scope:race",
        authorization_id="auth:race", asset_locator="https://inferred.invalid",
        asset_authorized=False, graph=SecurityKnowledgeGraph(), backend_available=False,
        capacity=10, exploration_fraction=1.0,
    )
    assert result.opportunities[0].prerequisite_state == "scope_confirmation_required"
    assert all(task.state is TaskState.WAITING_FOR_PREREQUISITE
               for task in result.missions[0].tasks)
