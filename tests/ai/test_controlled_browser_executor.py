from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.ai.agentic_os import (
    AuthorizationEnvelope,
    Budget,
    mint_execution_grant,
    process_grant_verifier,
)
from aegis.ai.jarvis.controlled_browser_executor import (
    ControlledBrowserCapture,
    ControlledBrowserWorkflowExecutor,
    RegisteredBrowserExperiment,
)
from aegis.ai.jarvis.mission_scheduler import MissionPlan, MissionTask
from aegis.ai.jarvis.oauth_intelligence import AuthWorkflowOutcome, OAuthClientPolicy
from aegis.browser import BrowserWorkflow, StepType, WorkflowStep

SCOPE = "scope:browser"


def _authorization():
    verifier = process_grant_verifier()
    budget = Budget(max_cost_usd=1, max_requests=8, max_human_minutes=3)
    grant = mint_execution_grant(
        type("AllowedPolicyDecision", (), {"allowed": True})(),
        scope_digest=SCOPE, budget=budget, verifier=verifier,
        network=True, state_change=True, human_approval=True,
    )
    return verifier, AuthorizationEnvelope(scope_digest=SCOPE, budget=budget, grant=grant)


def _experiment(capability):
    policy = OAuthClientPolicy(
        "client-1", ("https://app.example.test/callback",),
        require_state=True, require_nonce=True, require_pkce=True,
        allowed_postmessage_origins=("https://id.example.test",),
        evidence=("operator-client-registration",),
    )
    return RegisteredBrowserExperiment(
        "browser-exp", capability, SCOPE, "https://app.example.test",
        BrowserWorkflow(
            (WorkflowStep(StepType.NAVIGATE, {"url": "/authorize"}),),
            identity="synthetic-owner",
        ),
        True, ("scope-confirmed:app.example.test",),
        oauth_policy=(policy if capability.startswith(("dynamic:oauth", "dynamic:postmessage"))
                      else None),
    )


class Backend:
    def __init__(self, fields):
        self.fields = fields
        self.calls = []

    def execute(self, experiment, *, inputs):
        self.calls.append((experiment.experiment_id, dict(inputs)))
        return ControlledBrowserCapture(
            200, "https://app.example.test/callback", "a" * 64, "b" * 64,
            ("artifact://redacted.html", "artifact://masked.png"),
            self.fields, ("network:sha256",),
        )


def _task(capability, inputs=None):
    return MissionTask(
        "task:browser", "authentication", "controlled browser workflow",
        executor_capability=capability, risk="controlled_state_change", expected_requests=4,
        payload={"experiment_id": "browser-exp", "inputs": inputs or {}},
    )


def _plan(task):
    return MissionPlan("mission:browser", SCOPE, "verify auth workflow", (task,))


def _run(capability, fields, inputs=None):
    verifier, authorization = _authorization()
    backend = Backend(fields)
    executor = ControlledBrowserWorkflowExecutor(
        backend, experiments={"browser-exp": _experiment(capability)}, grant_verifier=verifier,
    )
    task = _task(capability, inputs)
    return executor(task, _plan(task), authorization), backend


def test_oauth_workflow_validates_redirect_state_nonce_and_pkce_with_redacted_artifacts():
    inputs = {
        "redirect_uri": "https://app.example.test/callback",
        "state": "synthetic-state", "nonce": "synthetic-nonce",
        "pkce_challenge": "synthetic-challenge", "pkce_method": "S256",
    }
    outcome, backend = _run("dynamic:oauth-trust-differential", {
        "authorization_accepted": True,
        "state_returned": "synthetic-state",
        "nonce_returned": "synthetic-nonce",
    }, inputs)
    assert {row.check for row in outcome.verdicts} == {"redirect_uri", "state", "nonce", "pkce"}
    assert all(row.outcome is AuthWorkflowOutcome.CONSISTENT for row in outcome.verdicts)
    assert backend.calls == [("browser-exp", inputs)]
    serialized = "".join(bundle.model_dump_json() for bundle in outcome.evidence)
    assert "synthetic-state" not in serialized and "masked.png" in serialized


def test_postmessage_wildcard_origin_is_a_positive_violation():
    outcome, _ = _run("dynamic:postmessage-trust-differential", {
        "authorization_accepted": True,
        "postmessage_sender_origin": "https://evil.example.test",
        "postmessage_target_origin": "*",
        "postmessage_sensitive_payload": True,
    }, {"redirect_uri": "https://app.example.test/callback"})
    assert len(outcome.verdicts) == 1
    assert outcome.verdicts[0].check == "postmessage_origin"
    assert outcome.verdicts[0].outcome is AuthWorkflowOutcome.VIOLATION


def test_recovery_and_session_invalidation_use_real_structured_observations():
    recovery, _ = _run("dynamic:recovery-state-differential", {
        "recovery_token_digest": "digest-only", "first_use_succeeded": True,
        "reuse_succeeded": False, "old_session_usable_after_reset": False,
    })
    assert len(recovery.verdicts) == 2
    assert all(row.outcome is AuthWorkflowOutcome.CONSISTENT for row in recovery.verdicts)

    session, _ = _run("dynamic:session-invalidation-differential", {
        "session_digest": "digest-only", "event": "password_reset",
        "usable_before": True, "usable_after": True,
    })
    assert session.verdicts[0].outcome is AuthWorkflowOutcome.VIOLATION


def test_browser_missing_registration_secrets_and_grant_fail_closed():
    verifier, authorization = _authorization()
    executor = ControlledBrowserWorkflowExecutor(Backend({}), experiments={}, grant_verifier=verifier)
    task = _task("dynamic:oauth-trust-differential")
    with pytest.raises(RuntimeError, match="registered browser experiment"):
        executor(task, _plan(task), authorization)

    executor = ControlledBrowserWorkflowExecutor(
        Backend({}), experiments={"browser-exp": _experiment(task.executor_capability)},
        grant_verifier=verifier,
    )
    secret_task = replace(task, payload={"experiment_id": "browser-exp", "inputs": {"token": "x"}})
    with pytest.raises(RuntimeError, match="credential references"):
        executor(secret_task, _plan(secret_task), authorization)
    with pytest.raises(PermissionError, match="exact verified"):
        executor(
            task, _plan(task), AuthorizationEnvelope(scope_digest=SCOPE, budget=authorization.budget),
        )
