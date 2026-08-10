from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from aegis.ai.agentic_os import (
    AuthorizationEnvelope,
    Budget,
    mint_execution_grant,
    process_grant_verifier,
)
from aegis.ai.jarvis.mission_scheduler import MissionPlan, MissionTask
from aegis.ai.jarvis.scoped_http_executor import ScopedEgressHttpExecutor
from aegis.ai.jarvis.vhost_executor import (
    ConfirmedVHost,
    RegisteredVHostExperiment,
    ScopedVHostRoutingExecutor,
)
from aegis.egress.app import EgressServiceConfig, UpstreamResponse, create_egress_app
from aegis.egress.auth import EgressClaims, issue_token
from aegis.gateway import NetworkProfile

SCOPE = "scope:vhost"
SECRET = "vhost-test-signing-secret-that-is-long-enough"
IP = "93.184.216.34"


def _authorization():
    verifier = process_grant_verifier()
    budget = Budget(max_cost_usd=1, max_requests=2, max_human_minutes=1)
    grant = mint_execution_grant(
        type("AllowedPolicyDecision", (), {"allowed": True})(),
        scope_digest=SCOPE, budget=budget, verifier=verifier,
        network=True, state_change=False, human_approval=True,
    )
    return verifier, AuthorizationEnvelope(scope_digest=SCOPE, budget=budget, grant=grant)


def _executor(*, candidate_ip=IP, registered=True):
    def resolver(host):
        return [candidate_ip if host == "admin.example.test" else IP]

    def sender(_method, url, pinned_ip, _headers, _body):
        body = b"admin route" if "admin.example.test" in url else b"default route"
        return UpstreamResponse(200, {"content-type": "text/plain"}, body)

    app = create_egress_app(EgressServiceConfig(SECRET), resolver=resolver, sender=sender)
    client = TestClient(app)

    def token_issuer(_action, method, destination, authorization):
        now = int(time.time())
        return issue_token(EgressClaims(
            tenant_id="tenant-a", engagement_id="eng-vhost",
            profile=NetworkProfile.TARGET_OBSERVATION.value,
            method=method, destination=destination, issued_at=now, expires_at=now + 60,
            budget_id="budget-vhost", request_limit=authorization.budget.max_requests,
            scope=[IP, "admin.example.test"], allowed_methods=[method],
        ), SECRET, now=now)

    verifier, _ = _authorization()
    http = ScopedEgressHttpExecutor(
        "https://egress.internal", token_issuer=token_issuer,
        grant_verifier=verifier, client=client,
    )
    experiment = RegisteredVHostExperiment(
        "vhost-1", SCOPE, IP, "http", "/health",
        (ConfirmedVHost("admin.example.test", ("scope-confirmed:admin.example.test",)),),
        ("authorized-ip:93.184.216.34",),
    )
    return ScopedVHostRoutingExecutor(
        http, experiments=({"vhost-1": experiment} if registered else {}),
        grant_verifier=verifier,
    )


def _task():
    return MissionTask(
        "task:vhost", "recon", "vhost routing differential", risk="read_only",
        executor_capability=ScopedVHostRoutingExecutor.CAPABILITY,
        expected_requests=2, payload={"experiment_id": "vhost-1"},
    )


def test_vhost_compares_only_confirmed_hostname_on_same_pinned_ip():
    executor = _executor()
    _, authorization = _authorization()
    task = _task()
    outcome = executor(task, MissionPlan("mission:vhost", SCOPE, "vhost", (task,)), authorization)
    assert outcome.observations[0].hostname == "admin.example.test"
    assert outcome.observations[0].pinned_ip == IP
    assert outcome.observations[0].differs_from_baseline
    assert outcome.evidence[0].steps[1].sanitized


def test_vhost_changed_resolution_missing_registration_and_grant_fail_closed():
    task = _task()
    _, authorization = _authorization()
    executor = _executor(candidate_ip="93.184.216.35")
    with pytest.raises(PermissionError, match="did not resolve to registered IP"):
        executor(task, MissionPlan("mission:wrong-ip", SCOPE, "vhost", (task,)), authorization)

    executor = _executor(registered=False)
    with pytest.raises(RuntimeError, match="not registered"):
        executor(task, MissionPlan("mission:missing", SCOPE, "vhost", (task,)), authorization)

    executor = _executor()
    with pytest.raises(PermissionError, match="exact verified"):
        executor(task, MissionPlan("mission:no-grant", SCOPE, "vhost", (task,)),
                 AuthorizationEnvelope(scope_digest=SCOPE, budget=authorization.budget))
