from __future__ import annotations

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
    FixtureExpectation,
    FixtureKind,
    FixtureProtocol,
    ProtocolBinding,
)
from aegis.ai.jarvis.identity_intelligence import DifferentialOutcome, ExpectedAccess
from aegis.ai.jarvis.mission_scheduler import MissionPlan, MissionTask
from aegis.ai.jarvis.production_dispatcher import (
    compose_production_executors,
    production_execution_coverage,
)
from aegis.ai.jarvis.websocket_executor import (
    POLICY_ACTION,
    ScopedWebSocketTransport,
    WebSocketIdentityDifferentialExecutor,
)
from aegis.egress.app import EgressServiceConfig, WebSocketResponse, create_egress_app
from aegis.egress.auth import EgressClaims, issue_token
from aegis.gateway import NetworkProfile

SCOPE = "scope:websocket"
SECRET = "websocket-test-signing-secret-that-is-long-enough"
ENDPOINT = "wss://socket.example.test/events"


def _authorization(*, requests: int = 8):
    verifier = process_grant_verifier()
    budget = Budget(max_cost_usd=1, max_requests=requests, max_human_minutes=2)
    grant = mint_execution_grant(
        type("AllowedPolicyDecision", (), {"allowed": True})(),
        scope_digest=SCOPE,
        budget=budget,
        verifier=verifier,
        network=True,
        state_change=True,
        human_approval=True,
    )
    return verifier, AuthorizationEnvelope(scope_digest=SCOPE, budget=budget, grant=grant)


def _fixtures(*, binding: bool = True):
    def identity(kind, principal):
        return ControlledIdentityFixture(
            kind,
            principal,
            "member",
            "tenant-a",
            CredentialReference(
                f"vault://identities/{principal}", SCOPE, (f"operator:{principal}",),
            ),
        )

    return ControlledIdentityFixtureSet(
        scope_digest=SCOPE,
        fixtures=(
            identity(FixtureKind.OWNER, "owner"),
            identity(FixtureKind.FOREIGN_SAME_ROLE, "peer"),
        ),
        bindings=((ProtocolBinding(
            FixtureProtocol.WEBSOCKET, ENDPOINT, ("scope-confirmed:socket.example.test",),
        ),) if binding else ()),
        expectations=(FixtureExpectation(
            "invoice.events", FixtureKind.FOREIGN_SAME_ROLE, "invoice-1",
            ExpectedAccess.DENY, ("policy:owner-channel",),
        ),),
    )


def _task():
    return MissionTask(
        "task:websocket",
        "authorization",
        "controlled WebSocket state differential",
        executor_capability=WebSocketIdentityDifferentialExecutor.CAPABILITY,
        risk="controlled_state_change",
        expected_requests=8,
        payload={
            "fixture_set_id": "fixtures:websocket",
            "operation": "invoice.events",
            "resource": {
                "resource_id": "invoice-1",
                "owner_id": "owner",
                "tenant": "tenant-a",
                "canary": "AEGIS-WS-CANARY-1",
                "synthetic": True,
            },
            "subscription_template": '{"op":"subscribe","channel":"{resource_id}"}',
            "message_template": '{"op":"read","channel":"{resource_id}"}',
            "state_recheck_template": '{"op":"state","channel":"{resource_id}"}',
            "denial_markers": ["forbidden"],
        },
    )


def _plan(task=None):
    return MissionPlan(
        "mission:websocket", SCOPE, "verify WebSocket authorization", (task or _task(),),
    )


def _executor(*, expose_to_peer: bool, binding: bool = True, observed=None):
    def websocket_sender(url, pinned_ip, headers, messages, receive_limit, timeout_seconds):
        if observed is not None:
            observed.append((url, pinned_ip, dict(headers), tuple(messages), receive_limit,
                             timeout_seconds))
        identity = headers["authorization"].removeprefix("Bearer ")
        returned = ["subscribed"]
        returned.append("AEGIS-WS-CANARY-1" if identity == "owner" or expose_to_peer
                        else "forbidden")
        returned.append("state:active")
        return WebSocketResponse(
            handshake_status=101,
            selected_protocol="aegis-json",
            messages=returned,
            close_code=1000,
        )

    app = create_egress_app(
        EgressServiceConfig(SECRET),
        resolver=lambda _host: ["93.184.216.34"],
        websocket_sender=websocket_sender,
    )
    client = TestClient(app)

    def token_issuer(action, destination, authorization):
        assert action == POLICY_ACTION
        now = int(time.time())
        return issue_token(EgressClaims(
            tenant_id="tenant-a",
            engagement_id="engagement-websocket",
            profile=NetworkProfile.TARGET_MUTATION.value,
            method="GET",
            destination=destination,
            issued_at=now,
            expires_at=now + 60,
            budget_id="budget-websocket",
            request_limit=authorization.budget.max_requests,
            scope=["socket.example.test"],
            allowed_methods=["GET"],
        ), SECRET, now=now)

    verifier, _ = _authorization()
    transport = ScopedWebSocketTransport(
        "https://egress.internal",
        token_issuer=token_issuer,
        grant_verifier=verifier,
        client=client,
    )
    return WebSocketIdentityDifferentialExecutor(
        transport,
        fixture_sets={"fixtures:websocket": _fixtures(binding=binding)},
        credential_resolver=lambda reference: {
            "authorization": f"Bearer {reference.rsplit('/', 1)[-1]}",
        },
        grant_verifier=verifier,
    )


def test_websocket_negative_control_checks_handshake_messages_and_state():
    observed = []
    executor = _executor(expose_to_peer=False, observed=observed)
    _, authorization = _authorization()
    outcome = executor(_task(), _plan(), authorization)
    assert outcome.verdicts[0].outcome is DifferentialOutcome.CONSISTENT
    assert outcome.observations[0].returned_markers == ("AEGIS-WS-CANARY-1",)
    assert outcome.observations[1].returned_markers == ()
    assert len(observed) == 2
    assert all(row[1] == "93.184.216.34" and len(row[3]) == 3 for row in observed)
    serialized = outcome.evidence[0].model_dump_json()
    assert "Bearer owner" not in serialized and "Bearer peer" not in serialized
    assert "state re-check" in serialized


def test_websocket_cross_identity_canary_is_a_positive_violation():
    executor = _executor(expose_to_peer=True)
    _, authorization = _authorization()
    outcome = executor(_task(), _plan(), authorization)
    assert outcome.verdicts[0].outcome is DifferentialOutcome.VIOLATION
    assert outcome.evidence[0].is_reproducible


def test_websocket_missing_binding_and_budget_fail_closed():
    executor = _executor(expose_to_peer=False, binding=False)
    _, authorization = _authorization()
    with pytest.raises(RuntimeError, match="binding"):
        executor(_task(), _plan(), authorization)

    executor = _executor(expose_to_peer=False)
    _, authorization = _authorization(requests=7)
    with pytest.raises(RuntimeError, match="budget exhausted"):
        executor(_task(), _plan(), authorization)


def test_websocket_exact_capability_and_signed_grant_are_enforced():
    executor = _executor(expose_to_peer=False)
    _, authorization = _authorization()
    wrong = replace(_task(), executor_capability="dynamic:graphql-auth-differential")
    with pytest.raises(PermissionError, match="exact verified grant"):
        executor(wrong, _plan(wrong), authorization)
    with pytest.raises(PermissionError, match="exact verified grant"):
        executor(
            _task(), _plan(), AuthorizationEnvelope(scope_digest=SCOPE, budget=authorization.budget),
        )


def test_websocket_executor_registers_as_real_production_capability():
    executor = _executor(expose_to_peer=False)
    registered = compose_production_executors((executor,))
    coverage = {row.capability: row.status for row in production_execution_coverage(registered)}
    assert coverage[WebSocketIdentityDifferentialExecutor.CAPABILITY] == "REAL"
