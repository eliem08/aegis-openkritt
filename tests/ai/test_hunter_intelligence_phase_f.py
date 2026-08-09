from aegis.ai.agentic_os import SecurityKnowledgeGraph
from aegis.ai.jarvis.hunter_phase_f import HunterIntelligencePhaseF
from aegis.ai.jarvis.mission_scheduler import TaskState
from aegis.ai.jarvis.oauth_intelligence import (
    AuthWorkflowOutcome,
    OAuthClientPolicy,
    OAuthFlowObservation,
    OAuthTrustGraphAgent,
    RecoveryObservation,
    SessionInvalidationObservation,
)
from aegis.ingest.program import ProgramRules

POLICY = OAuthClientPolicy(
    "client-web", ("https://app.example.test/callback",),
    require_state=True, require_nonce=True, require_pkce=True,
    allowed_postmessage_origins=("https://app.example.test",),
    evidence=("client-registration:sha256",),
)


def _flow(**overrides):
    values = dict(
        flow_id="flow-1", policy=POLICY,
        supplied_redirect_uri="https://evil.invalid/callback",
        authorization_accepted=True, state_sent_digest="state-a",
        state_returned_digest="state-b", nonce_sent_digest="nonce-a",
        nonce_returned_digest="", pkce_challenge_digest="", pkce_method="plain",
        postmessage_sender_origin="https://evil.invalid",
        postmessage_target_origin="*", postmessage_sensitive_payload=True,
        synthetic_account=True, authorized=True, evidence=("capture:oauth",),
    )
    values.update(overrides)
    return OAuthFlowObservation(**values)


def test_oauth_agent_detects_redirect_state_nonce_pkce_and_message_trust_failures():
    verdicts = OAuthTrustGraphAgent().analyze_flow(_flow())
    violations = {row.check for row in verdicts
                  if row.outcome is AuthWorkflowOutcome.VIOLATION}
    assert violations == {"redirect_uri", "state", "nonce", "pkce", "postmessage_origin"}


def test_oauth_positive_control_is_consistent():
    row = _flow(
        supplied_redirect_uri="https://app.example.test/callback",
        state_returned_digest="state-a", nonce_returned_digest="nonce-a",
        pkce_challenge_digest="challenge", pkce_method="S256",
        postmessage_sender_origin="https://app.example.test",
        postmessage_target_origin="https://app.example.test",
    )
    assert {item.outcome for item in OAuthTrustGraphAgent().analyze_flow(row)} == {
        AuthWorkflowOutcome.CONSISTENT
    }


def test_auth_workflow_fails_closed_without_policy_or_synthetic_authorization():
    verdicts = OAuthTrustGraphAgent().analyze_flow(_flow(authorized=False))
    assert len(verdicts) == 1
    assert verdicts[0].outcome is AuthWorkflowOutcome.INCONCLUSIVE


def test_recovery_reuse_and_session_invalidation_are_verified_separately():
    recovery = RecoveryObservation(
        "reset-1", "sha256:token", True, True, True, True, True,
        ("capture:first", "capture:reuse", "capture:old-session"),
    )
    verdicts = OAuthTrustGraphAgent().analyze_recovery(recovery)
    assert {row.check for row in verdicts if row.outcome is AuthWorkflowOutcome.VIOLATION} == {
        "recovery_token_reuse", "reset_session_invalidation"
    }
    session = SessionInvalidationObservation(
        "logout-1", "sha256:session", "logout", True, True, True, True,
        ("capture:logout", "capture:post-logout"),
    )
    assert OAuthTrustGraphAgent().analyze_session(session).outcome is (
        AuthWorkflowOutcome.VIOLATION
    )


def test_phase_f_compiles_oauth_violations_into_canonical_missions():
    graph = SecurityKnowledgeGraph()
    result = HunterIntelligencePhaseF().run(
        program=ProgramRules(handle="oauth-lab"), scope_digest="scope:oauth",
        authorization_id="auth:oauth", asset_locator="https://auth.example.test",
        asset_authorized=True, graph=graph, oauth_flows=(_flow(),),
        capacity=20, exploration_fraction=1.0,
    )
    assert len(result.opportunities) == 5
    assert all(row.estimated_payout_usd is None for row in result.opportunities)
    postmessage = next(row for row in result.opportunities
                       if row.metadata["check"] == "postmessage_origin")
    mission = next(row for row in result.missions
                   if row.opportunity_id == postmessage.opportunity_id)
    assert mission.tasks[0].executor_capability == "dynamic:postmessage-trust-differential"
    assert mission.tasks[0].state is TaskState.PENDING
    assert graph.nodes[postmessage.opportunity_id]["kind"] == "hunt_opportunity"


def test_phase_f_missing_backend_and_inferred_asset_wait_fail_closed():
    result = HunterIntelligencePhaseF().run(
        program=ProgramRules(handle="oauth-lab"), scope_digest="scope:oauth",
        authorization_id="auth:oauth", asset_locator="https://inferred.invalid",
        asset_authorized=False, graph=SecurityKnowledgeGraph(), backend_available=False,
        capacity=10, exploration_fraction=1.0,
    )
    assert result.opportunities[0].prerequisite_state == "scope_confirmation_required"
    assert all(task.state is TaskState.WAITING_FOR_PREREQUISITE
               for task in result.missions[0].tasks)
