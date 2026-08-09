from __future__ import annotations

import time

from fastapi.testclient import TestClient

from aegis.ai.agentic_os import (
    AuthorizationEnvelope,
    Budget,
    mint_execution_grant,
    process_grant_verifier,
)
from aegis.ai.jarvis.asset_execution_ticket import CapabilityAvailability
from aegis.ai.jarvis.http_identity_executor import (
    HttpIdentityDifferentialExecutor,
    HttpIdentityExecutionOutcome,
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
from aegis.ai.jarvis.mission_capabilities import CapabilityDisposition
from aegis.ai.jarvis.mission_scheduler import MissionPlan, MissionScheduler, MissionTask
from aegis.ai.jarvis.scoped_http_executor import POLICY_ACTION, ScopedEgressHttpExecutor
from aegis.ai.jarvis.state_store import JarvisStateStore
from aegis.ai.jarvis.universal_runtime import UniversalMissionRuntime
from aegis.egress.app import EgressServiceConfig, UpstreamResponse, create_egress_app
from aegis.egress.auth import EgressClaims, issue_token
from aegis.gateway import NetworkProfile

SCOPE = "scope:http-identity"
SECRET = "test-egress-signing-key-that-is-long-enough"
CAPABILITY = "dynamic:identity-object-differential"


def _authorization():
    verifier = process_grant_verifier()
    budget = Budget(max_cost_usd=1, max_requests=4, max_human_minutes=2)
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


def _fixture_set():
    def fixture(kind, principal):
        return ControlledIdentityFixture(
            kind,
            principal,
            "member",
            "tenant-a",
            CredentialReference(f"vault://identities/{principal}", SCOPE, (f"operator:{principal}",)),
        )

    return ControlledIdentityFixtureSet(
        scope_digest=SCOPE,
        fixtures=(
            fixture(FixtureKind.OWNER, "owner"),
            fixture(FixtureKind.FOREIGN_SAME_ROLE, "peer"),
        ),
        bindings=(ProtocolBinding(
            FixtureProtocol.HTTP,
            "https://api.example.test/invoices/{resource_id}",
            ("scope-confirmed:api.example.test",),
        ),),
        expectations=(FixtureExpectation(
            "invoice.read",
            FixtureKind.FOREIGN_SAME_ROLE,
            "invoice-1",
            ExpectedAccess.DENY,
            ("policy:owner-only",),
        ),),
    )


def _task():
    return MissionTask(
        "task:http-auth",
        "authorization",
        "controlled identity differential",
        opportunity_id="opp:http-auth",
        asset_id="asset:api",
        asset_kind="api",
        asset_locator="https://api.example.test",
        executor_capability=CAPABILITY,
        risk="controlled_state_change",
        expected_requests=2,
        payload={
            "fixture_set_id": "fixtures:http",
            "operation": "invoice.read",
            "method": "GET",
            "resource": {
                "resource_id": "invoice-1",
                "owner_id": "owner",
                "tenant": "tenant-a",
                "canary": "AEGIS-CANARY-HTTP-1",
                "synthetic": True,
            },
        },
    )


def _plan(task):
    return MissionPlan(
        "mission:http-auth",
        SCOPE,
        "verify controlled object authorization",
        (task,),
        opportunity_id="opp:http-auth",
        asset_id="asset:api",
        asset_kind="api",
        authorization_id="authorization:http-auth",
    )


def _executor(*, expose_to_peer: bool):
    def sender(_method, _url, _ip, headers, _body):
        identity = headers["authorization"].removeprefix("Bearer ")
        if identity == "owner" or expose_to_peer:
            return UpstreamResponse(200, {"content-type": "application/json"}, b'"AEGIS-CANARY-HTTP-1"')
        return UpstreamResponse(403, {"content-type": "application/json"}, b'{"denied":true}')

    app = create_egress_app(
        EgressServiceConfig(SECRET),
        resolver=lambda _host: ["93.184.216.34"],
        sender=sender,
    )
    client = TestClient(app)

    def token_issuer(action, method, destination, authorization):
        assert action == POLICY_ACTION
        now = int(time.time())
        return issue_token(EgressClaims(
            tenant_id="tenant-a",
            engagement_id="engagement-http",
            profile=NetworkProfile.TARGET_OBSERVATION.value,
            method=method,
            destination=destination,
            issued_at=now,
            expires_at=now + 60,
            budget_id="budget-http",
            request_limit=authorization.budget.max_requests,
            scope=["api.example.test"],
            allowed_methods=["GET"],
        ), SECRET, now=now)

    verifier, _ = _authorization()
    http = ScopedEgressHttpExecutor(
        "https://egress.internal",
        token_issuer=token_issuer,
        grant_verifier=verifier,
        client=client,
    )
    return HttpIdentityDifferentialExecutor(
        http,
        fixture_sets={"fixtures:http": _fixture_set()},
        credential_resolver=lambda reference: {
            "authorization": f"Bearer {reference.rsplit('/', 1)[-1]}"
        },
        grant_verifier=verifier,
    )


def test_real_scoped_http_negative_control_is_consistent_and_sanitized():
    executor = _executor(expose_to_peer=False)
    _, authorization = _authorization()
    outcome = executor(_task(), _plan(_task()), authorization)
    assert outcome.verdicts[0].outcome is DifferentialOutcome.CONSISTENT
    assert outcome.observations[0].returned_markers == ("AEGIS-CANARY-HTTP-1",)
    assert outcome.observations[1].returned_markers == ()
    serialized = outcome.evidence[0].model_dump_json()
    assert "Bearer owner" not in serialized and "Bearer peer" not in serialized


def test_real_scoped_http_canary_exposure_is_a_positive_violation():
    executor = _executor(expose_to_peer=True)
    _, authorization = _authorization()
    outcome = executor(_task(), _plan(_task()), authorization)
    assert outcome.verdicts[0].outcome is DifferentialOutcome.VIOLATION
    assert outcome.evidence[0].is_reproducible


def test_runtime_retains_dynamic_evidence_and_missing_fixture_waits(tmp_path):
    executor = _executor(expose_to_peer=False)
    verifier, authorization = _authorization()
    with JarvisStateStore(tmp_path / "jarvis.db") as store:
        runtime = UniversalMissionRuntime(
            MissionScheduler(store),
            grant_verifier=verifier,
            mission_task_executors={CAPABILITY: executor},
        )
        plan = runtime.scheduler.create(_plan(_task()))
        result = runtime.execute_first(
            plan,
            authorization=authorization,
            availability=CapabilityAvailability(),
        )
        assert result.disposition is CapabilityDisposition.READY
        assert isinstance(result.outcome, HttpIdentityExecutionOutcome)

        missing = HttpIdentityDifferentialExecutor(
            executor.http,
            fixture_sets={},
            credential_resolver=lambda _reference: {},
            grant_verifier=verifier,
        )
        runtime = UniversalMissionRuntime(
            MissionScheduler(store),
            grant_verifier=verifier,
            mission_task_executors={CAPABILITY: missing},
        )
        waiting_plan = runtime.scheduler.create(
            MissionPlan(
                "mission:http-auth-missing",
                SCOPE,
                "missing fixture must not succeed",
                (_task(),),
            )
        )
        waiting = runtime.execute_first(
            waiting_plan,
            authorization=authorization,
            availability=CapabilityAvailability(),
        )
    assert waiting.disposition is CapabilityDisposition.WAITING_FOR_PREREQUISITE
    assert waiting.plan.tasks[0].state.value == "waiting_for_prerequisite"
