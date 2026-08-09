from __future__ import annotations

import json
import time
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from aegis.ai.agentic_os import (
    AuthorizationEnvelope,
    Budget,
    mint_execution_grant,
    process_grant_verifier,
)
from aegis.ai.jarvis.identity_fixtures import (
    ControlledIdentityFixture,
    ControlledIdentityFixtureSet,
    CredentialReference,
    FixtureKind,
    FixtureProtocol,
    ProtocolBinding,
)
from aegis.ai.jarvis.identity_intelligence import StateVerificationOutcome
from aegis.ai.jarvis.lifecycle_executor import ScopedLifecycleStateExecutor
from aegis.ai.jarvis.mission_scheduler import MissionPlan, MissionTask
from aegis.egress.app import EgressServiceConfig, UpstreamResponse, create_egress_app
from aegis.egress.auth import EgressClaims, issue_token
from aegis.gateway import NetworkProfile

SCOPE = "scope:lifecycle"
SECRET = "lifecycle-test-signing-key-that-is-long-enough"


def _authorization(requests=3):
    verifier = process_grant_verifier()
    budget = Budget(max_cost_usd=1, max_requests=requests, max_human_minutes=2)
    grant = mint_execution_grant(
        type("AllowedPolicyDecision", (), {"allowed": True})(),
        scope_digest=SCOPE, budget=budget, verifier=verifier,
        network=True, state_change=True, human_approval=True,
    )
    return verifier, AuthorizationEnvelope(scope_digest=SCOPE, budget=budget, grant=grant)


def _fixtures():
    return ControlledIdentityFixtureSet(
        scope_digest=SCOPE,
        fixtures=(ControlledIdentityFixture(
            FixtureKind.OWNER, "owner", "member", "tenant-a",
            CredentialReference("vault://identities/owner", SCOPE, ("operator:owner",)),
        ),),
        bindings=(ProtocolBinding(
            FixtureProtocol.HTTP, "https://api.example.test/",
            ("scope-confirmed:api.example.test",),
        ),),
    )


def _task(capability, **payload_overrides):
    payload = {
        "fixture_set_id": "fixtures:lifecycle",
        "fixture_kind": "owner",
        "operation": "invoice.approve",
        "resource": {
            "resource_id": "invoice-1", "owner_id": "owner", "tenant": "tenant-a",
            "canary": "AEGIS-LIFECYCLE-CANARY-1", "synthetic": True,
        },
        "pre_state": {"method": "GET", "path": "/state"},
        "action": {"method": "POST", "path": "/approve", "body_template": "{}"},
        "post_state": {"method": "GET", "path": "/state"},
    }
    payload.update(payload_overrides)
    return MissionTask(
        "task:lifecycle", "business_logic", "bounded lifecycle verification",
        executor_capability=capability, risk="controlled_state_change",
        expected_requests=3, payload=payload,
    )


def _plan(task):
    return MissionPlan("mission:lifecycle", SCOPE, "verify transaction state", (task,))


def _executor(mode):
    state = {
        "status": "pending", "ledger": "pending", "outbox": "pending",
        "marker": "AEGIS-LIFECYCLE-CANARY-1",
    }
    state_reads = 0

    def sender(method, url, _ip, headers, _body):
        nonlocal state_reads
        assert headers["authorization"] == "Bearer owner"
        if url.endswith("/state"):
            state_reads += 1
            return UpstreamResponse(200, {"content-type": "application/json"},
                                    json.dumps(state, sort_keys=True).encode())
        assert method == "POST" and url.endswith("/approve")
        state["status"] = "approved"
        state["ledger"] = "committed"
        if mode != "partial":
            state["outbox"] = "committed"
        return UpstreamResponse(500 if mode == "error" else 200,
                                {"content-type": "application/json"}, b'{"accepted":true}')

    app = create_egress_app(
        EgressServiceConfig(SECRET), resolver=lambda _host: ["93.184.216.34"], sender=sender,
    )
    client = TestClient(app)

    def token_issuer(action, method, destination, authorization):
        now = int(time.time())
        return issue_token(EgressClaims(
            tenant_id="tenant-a", engagement_id="eng-lifecycle",
            profile=NetworkProfile.TARGET_MUTATION.value,
            method=method, destination=destination, issued_at=now, expires_at=now + 60,
            budget_id="budget-lifecycle", request_limit=authorization.budget.max_requests,
            scope=["api.example.test"], allowed_methods=[method],
        ), SECRET, now=now)

    verifier, _ = _authorization()
    from aegis.ai.jarvis.scoped_http_executor import ScopedEgressHttpExecutor
    http = ScopedEgressHttpExecutor(
        "https://egress.internal", token_issuer=token_issuer,
        grant_verifier=verifier, client=client,
    )
    return ScopedLifecycleStateExecutor(
        http, fixture_sets={"fixtures:lifecycle": _fixtures()},
        credential_resolver=lambda _ref: {"authorization": "Bearer owner"},
        grant_verifier=verifier,
    )


def test_5xx_with_persistent_state_change_is_hidden_commit_not_failure_hypothesis():
    task = _task("dynamic:post-error-state-verifier")
    executor = _executor("error")
    _, authorization = _authorization()
    outcome = executor(task, _plan(task), authorization)
    assert outcome.observation.status_code == 500
    assert outcome.verification.outcome is StateVerificationOutcome.HIDDEN_COMMIT
    assert outcome.evidence.is_reproducible


def test_partial_commit_uses_exact_post_state_effect_assertions():
    task = _task(
        "dynamic:partial-commit-verifier",
        expected_effects=["ledger", "outbox"],
        effect_assertions=[
            {"name": "ledger", "json_path": "ledger", "equals": "committed"},
            {"name": "outbox", "json_path": "outbox", "equals": "committed"},
        ],
    )
    executor = _executor("partial")
    _, authorization = _authorization()
    outcome = executor(task, _plan(task), authorization)
    assert outcome.observation.side_effects == ("ledger",)
    assert outcome.verification.outcome is StateVerificationOutcome.PARTIAL_COMMIT


def test_forbidden_lifecycle_transition_is_observed_from_real_readbacks():
    task = _task(
        "dynamic:lifecycle-state-differential",
        state_json_path="status", from_state="pending", to_state="approved",
        transition_allowed=False, transition_policy_evidence=["policy:approval-forbidden"],
    )
    executor = _executor("complete")
    _, authorization = _authorization()
    outcome = executor(task, _plan(task), authorization)
    assert outcome.transition is not None and outcome.transition.violation
    assert outcome.evidence.observed == "forbidden lifecycle transition completed"


def test_lifecycle_prerequisites_budget_and_grant_fail_closed():
    task = _task("dynamic:partial-commit-verifier")
    executor = _executor("partial")
    _, authorization = _authorization()
    with pytest.raises(RuntimeError, match="expected effects"):
        executor(task, _plan(task), authorization)

    malformed = replace(task, executor_capability="dynamic:post-error-state-verifier",
                        payload={**task.payload, "pre_state": {"path": "https://evil.test"}})
    with pytest.raises(RuntimeError, match="absolute local paths"):
        executor(malformed, _plan(malformed), authorization)

    executor = _executor("complete")
    _, too_small = _authorization(requests=2)
    normal = _task("dynamic:post-error-state-verifier")
    with pytest.raises(RuntimeError, match="request budget exhausted"):
        executor(normal, _plan(normal), too_small)

    with pytest.raises(PermissionError, match="exact verified"):
        executor(normal, _plan(normal), AuthorizationEnvelope(SCOPE, authorization.budget))
