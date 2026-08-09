from __future__ import annotations

from aegis.ai.agentic_os import (
    AuthorizationEnvelope,
    Budget,
    SecurityKnowledgeGraph,
    mint_execution_grant,
    process_grant_verifier,
)
from aegis.ai.jarvis.asset_execution_ticket import CapabilityAvailability
from aegis.ai.jarvis.hunter_phase_b import HunterIntelligencePhaseB
from aegis.ai.jarvis.identity_intelligence import (
    AccessObservation,
    AuthorizationMatrix,
    AuthorizationRule,
    ControlledPrincipal,
    DifferentialOutcome,
    ErrorStateVerifier,
    ExpectedAccess,
    IdentityDifferentialOracle,
    LifecycleStateAgent,
    LifecycleTransitionRule,
    StateVerificationOutcome,
    SyntheticResource,
)
from aegis.ai.jarvis.mission_capabilities import CapabilityDisposition
from aegis.ai.jarvis.mission_scheduler import MissionScheduler, TaskState
from aegis.ai.jarvis.state_store import JarvisStateStore
from aegis.ai.jarvis.universal_runtime import UniversalMissionRuntime
from aegis.ingest.program import ProgramRules

OWNER = ControlledPrincipal("owner", "member", "tenant-a", True, ("fixture:owner",))
PEER = ControlledPrincipal("peer", "member", "tenant-a", True, ("fixture:peer",))
OUTSIDER = ControlledPrincipal("outsider", "member", "tenant-b", True, ("fixture:outside",))
RESOURCE = SyntheticResource("invoice-1", "owner", "tenant-a", "canary-invoice-1")


def _observation(principal, *, status=200, markers=(), before="v1", after="v1",
                 effects=(), evidence=("capture:1",), correlation="request-1", timed_out=False):
    return AccessObservation(
        principal, RESOURCE, "invoice.read", status,
        response_digest="sha256:response", returned_markers=markers,
        before_state_digest=before, after_state_digest=after,
        side_effects=effects, evidence=evidence, correlation_id=correlation,
        timed_out=timed_out,
    )


def _matrix(principal=OUTSIDER):
    return AuthorizationMatrix((AuthorizationRule(
        "invoice.read", principal.principal_id, RESOURCE.resource_id,
        ExpectedAccess.DENY, ("program-policy:tenant-isolation",),
    ),))


def test_identity_oracle_requires_canary_or_state_effect_not_status_alone():
    oracle = IdentityDifferentialOracle()
    control = _observation(OWNER, markers=(RESOURCE.canary,), correlation="owner-control")
    violation = oracle.evaluate(
        control,
        _observation(OUTSIDER, markers=(RESOURCE.canary,), correlation="cross-tenant"),
        _matrix(),
    )
    assert violation.outcome is DifferentialOutcome.VIOLATION
    assert violation.dimension == "tenant"
    assert violation.confidence >= 0.95

    denied = oracle.evaluate(
        control, _observation(OUTSIDER, status=403, correlation="denied"), _matrix()
    )
    assert denied.outcome is DifferentialOutcome.CONSISTENT

    ambiguous = oracle.evaluate(
        control, _observation(OUTSIDER, status=200, correlation="empty-200"), _matrix()
    )
    assert ambiguous.outcome is DifferentialOutcome.INCONCLUSIVE


def test_identity_oracle_fails_closed_on_unknown_policy_or_uncontrolled_identity():
    oracle = IdentityDifferentialOracle()
    control = _observation(OWNER, markers=(RESOURCE.canary,), correlation="owner")
    unknown = oracle.evaluate(
        control, _observation(PEER, markers=(RESOURCE.canary,), correlation="peer"),
        AuthorizationMatrix(),
    )
    assert unknown.outcome is DifferentialOutcome.INCONCLUSIVE
    uncontrolled = ControlledPrincipal("guest", "member", "tenant-b")
    result = oracle.evaluate(
        control, _observation(uncontrolled, markers=(RESOURCE.canary,), correlation="guest"),
        _matrix(uncontrolled),
    )
    assert result.outcome is DifferentialOutcome.INCONCLUSIVE
    assert "control evidence" in result.reason


def test_error_state_verifier_detects_partial_commit_and_requires_readback():
    verifier = ErrorStateVerifier()
    partial = verifier.verify(
        _observation(
            OWNER, status=500, before="v1", after="v2", effects=("debit",),
            evidence=("capture:error", "snapshot:before", "snapshot:after"),
            correlation="compound-write",
        ),
        expected_effects=("debit", "ledger"),
    )
    assert partial.outcome is StateVerificationOutcome.PARTIAL_COMMIT
    no_readback = verifier.verify(
        _observation(OWNER, status=500, before="", after="", effects=("debit",)),
        expected_effects=("debit", "ledger"),
    )
    assert no_readback.outcome is StateVerificationOutcome.INCONCLUSIVE


def test_lifecycle_agent_selects_only_explicit_evidence_backed_reachable_negatives():
    rows = LifecycleStateAgent().hypotheses(
        (
            LifecycleTransitionRule("refund", "cancelled", "refunded", False,
                                    ("policy:no-refund-after-cancel",)),
            LifecycleTransitionRule("pay", "draft", "paid", True, ("docs:pay",)),
            LifecycleTransitionRule("ship", "draft", "shipped", False),
            LifecycleTransitionRule("archive", "unknown", "archived", False,
                                    ("docs:archive",)),
        ),
        observed_states=("draft", "cancelled", "refunded", "paid", "shipped"),
    )
    assert [(row.operation, row.from_state, row.to_state) for row in rows] == [
        ("refund", "cancelled", "refunded")
    ]


def test_phase_b_compiles_real_oracle_results_into_canonical_missions():
    control = _observation(OWNER, markers=(RESOURCE.canary,), correlation="owner")
    probe = _observation(
        OUTSIDER, markers=(RESOURCE.canary,), correlation="outside",
        evidence=("capture:owner", "capture:outside"),
    )
    graph = SecurityKnowledgeGraph()
    result = HunterIntelligencePhaseB().run(
        program=ProgramRules(handle="identity-lab"),
        scope_digest="scope:identity", authorization_id="auth:identity",
        asset_locator="https://api.example.test", asset_authorized=True, graph=graph,
        identity_pairs=((control, probe),), authorization_matrix=_matrix(),
        lifecycle_rules=(LifecycleTransitionRule(
            "refund", "cancelled", "refunded", False, ("policy:refund",)
        ),),
        observed_states=("cancelled", "refunded"),
        capacity=10, exploration_fraction=1.0,
    )
    assert result.authorization_verdicts[0].outcome is DifferentialOutcome.VIOLATION
    assert result.opportunities and all(row.estimated_payout_usd is None
                                        for row in result.opportunities)
    auth_opportunity = next(row for row in result.opportunities
                            if row.metadata["technique"] == "auth_tenant_differential")
    mission = next(row for row in result.missions
                   if row.opportunity_id == auth_opportunity.opportunity_id)
    assert mission.tasks[0].executor_capability == "dynamic:identity-tenant-differential"
    assert mission.tasks[0].risk == "controlled_state_change"
    assert mission.tasks[0].expected_requests == 2
    assert mission.tasks[0].state is TaskState.PENDING
    assert graph.nodes[auth_opportunity.opportunity_id]["kind"] == "hunt_opportunity"


def test_missing_identity_backend_and_unconfirmed_asset_wait_fail_closed():
    result = HunterIntelligencePhaseB().run(
        program=ProgramRules(handle="identity-lab"),
        scope_digest="scope:identity", authorization_id="auth:identity",
        asset_locator="https://inferred.invalid", asset_authorized=False,
        graph=SecurityKnowledgeGraph(), capacity=10, exploration_fraction=1.0,
    )
    assert len(result.opportunities) == 1
    assert result.opportunities[0].prerequisite_state == "scope_confirmation_required"
    assert all(task.state is TaskState.WAITING_FOR_PREREQUISITE
               for task in result.missions[0].tasks)


def test_canonical_runtime_dispatches_phase_b_only_with_signed_state_grant(tmp_path):
    control = _observation(OWNER, markers=(RESOURCE.canary,), correlation="owner")
    probe = _observation(OUTSIDER, markers=(RESOURCE.canary,), correlation="outside")
    phase = HunterIntelligencePhaseB().run(
        program=ProgramRules(handle="identity-lab"),
        scope_digest="scope:identity", authorization_id="auth:identity",
        asset_locator="https://api.example.test", asset_authorized=True,
        graph=SecurityKnowledgeGraph(), identity_pairs=((control, probe),),
        authorization_matrix=_matrix(), capacity=10, exploration_fraction=1.0,
    )
    opportunity = phase.opportunities[0]
    calls = []
    verifier = process_grant_verifier()
    budget = Budget(max_cost_usd=1, max_requests=4, max_human_minutes=1)
    with JarvisStateStore(tmp_path / "jarvis.db") as store:
        runtime = UniversalMissionRuntime(
            MissionScheduler(store), grant_verifier=verifier,
            mission_task_executors={
                opportunity.metadata["worker_capability"]:
                    lambda task, plan, authorization: calls.append(task.task_id)
            },
        )
        mission = runtime.prepare(opportunity, availability=CapabilityAvailability())
        denied = runtime.execute_first(
            mission,
            authorization=AuthorizationEnvelope(scope_digest="scope:identity", budget=budget),
            availability=CapabilityAvailability(),
        )
        assert denied.disposition is CapabilityDisposition.WAITING_FOR_APPROVAL
        assert calls == []

        grant = mint_execution_grant(
            type("AllowedPolicyDecision", (), {"allowed": True})(),
            scope_digest="scope:identity", budget=budget, verifier=verifier,
            network=True, state_change=True, human_approval=True,
        )
        allowed = runtime.execute_first(
            denied.plan,
            authorization=AuthorizationEnvelope(
                scope_digest="scope:identity", budget=budget, grant=grant
            ),
            availability=CapabilityAvailability(),
        )
        assert allowed.disposition is CapabilityDisposition.READY
        assert calls == [mission.tasks[0].task_id]
        assert allowed.plan.tasks[0].state is TaskState.COMPLETED


def test_missing_phase_b_executor_is_unavailable_not_success(tmp_path):
    control = _observation(OWNER, markers=(RESOURCE.canary,), correlation="owner")
    probe = _observation(OUTSIDER, markers=(RESOURCE.canary,), correlation="outside")
    phase = HunterIntelligencePhaseB().run(
        program=ProgramRules(handle="identity-lab"),
        scope_digest="scope:identity", authorization_id="auth:identity",
        asset_locator="https://api.example.test", asset_authorized=True,
        graph=SecurityKnowledgeGraph(), identity_pairs=((control, probe),),
        authorization_matrix=_matrix(), capacity=10, exploration_fraction=1.0,
    )
    verifier = process_grant_verifier()
    budget = Budget(max_cost_usd=1, max_requests=4, max_human_minutes=1)
    grant = mint_execution_grant(
        type("AllowedPolicyDecision", (), {"allowed": True})(),
        scope_digest="scope:identity", budget=budget, verifier=verifier,
        network=True, state_change=True, human_approval=True,
    )
    with JarvisStateStore(tmp_path / "jarvis.db") as store:
        runtime = UniversalMissionRuntime(MissionScheduler(store), grant_verifier=verifier)
        mission = runtime.prepare(phase.opportunities[0], availability=CapabilityAvailability())
        outcome = runtime.execute_first(
            mission,
            authorization=AuthorizationEnvelope(
                scope_digest="scope:identity", budget=budget, grant=grant
            ),
            availability=CapabilityAvailability(),
        )
    assert outcome.disposition is CapabilityDisposition.UNAVAILABLE
    assert outcome.plan.tasks[0].state is TaskState.UNAVAILABLE
    assert "no concrete executor" in outcome.reason
