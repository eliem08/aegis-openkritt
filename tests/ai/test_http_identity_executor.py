from __future__ import annotations

import json
import time
from dataclasses import replace
from datetime import UTC, datetime
from threading import Lock

from fastapi.testclient import TestClient

from aegis.ai.agentic_os import (
    AuthorizationEnvelope,
    Budget,
    mint_execution_grant,
    process_grant_verifier,
)
from aegis.ai.jarvis.asset_execution_ticket import CapabilityAvailability
from aegis.ai.jarvis.cache_executor import CacheDifferentialExecutor
from aegis.ai.jarvis.cache_intelligence import CacheOutcome
from aegis.ai.jarvis.graphql_identity_executor import GraphQLAuthorizationDifferentialExecutor
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
from aegis.ai.jarvis.production_dispatcher import (
    compose_production_executors,
    production_execution_coverage,
)
from aegis.ai.jarvis.race_executor import ScopedRaceIdempotencyExecutor
from aegis.ai.jarvis.race_intelligence import RaceOutcome
from aegis.ai.jarvis.scoped_http_executor import POLICY_ACTION, ScopedEgressHttpExecutor
from aegis.ai.jarvis.state_store import JarvisStateStore
from aegis.ai.jarvis.universal_runtime import UniversalMissionRuntime
from aegis.ai.jarvis.url_consumer_executor import ScopedURLConsumerExecutor
from aegis.ai.jarvis.url_consumer_intelligence import URLConsumerOutcome
from aegis.egress.app import EgressServiceConfig, UpstreamResponse, create_egress_app
from aegis.egress.auth import EgressClaims, issue_token
from aegis.gateway import NetworkProfile
from aegis.oast.models import Interaction
from aegis.oast.service import PrivateOastConfig, PrivateOastService

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
        bindings=(
            ProtocolBinding(
                FixtureProtocol.HTTP,
                "https://api.example.test/invoices/{resource_id}",
                ("scope-confirmed:api.example.test",),
            ),
            ProtocolBinding(
                FixtureProtocol.GRAPHQL,
                "https://api.example.test/graphql",
                ("scope-confirmed:api.example.test",),
            ),
        ),
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


def _executor(*, expose_to_peer: bool, graphql: bool = False, calls=None,
              sender_override=None):
    def sender(_method, _url, _ip, headers, _body):
        if calls is not None:
            calls.append((_method, _url, dict(headers), _body))
        if sender_override is not None:
            return sender_override(_method, _url, _ip, headers, _body)
        identity = headers["authorization"].removeprefix("Bearer ")
        if _url.endswith("/clean"):
            return UpstreamResponse(200, {"age": "1"}, b'{"clean":true}')
        if identity == "owner" or expose_to_peer:
            return UpstreamResponse(
                200, {"content-type": "application/json", "age": "2"},
                b'"AEGIS-CANARY-HTTP-1"',
            )
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
            profile=(NetworkProfile.TARGET_MUTATION.value if method == "POST"
                     else NetworkProfile.TARGET_OBSERVATION.value),
            method=method,
            destination=destination,
            issued_at=now,
            expires_at=now + 60,
            budget_id="budget-http",
            request_limit=authorization.budget.max_requests,
            scope=["api.example.test"],
            allowed_methods=[method],
        ), SECRET, now=now)

    verifier, _ = _authorization()
    http = ScopedEgressHttpExecutor(
        "https://egress.internal",
        token_issuer=token_issuer,
        grant_verifier=verifier,
        client=client,
    )
    executor_type = (
        GraphQLAuthorizationDifferentialExecutor if graphql
        else HttpIdentityDifferentialExecutor
    )
    return executor_type(
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


def test_graphql_differential_uses_scoped_post_and_canonical_oracle():
    calls = []
    executor = _executor(expose_to_peer=False, graphql=True, calls=calls)
    _, authorization = _authorization()
    payload = {
        **(_task().payload or {}),
        "query": "query Invoice($id: ID!) { invoice(id: $id) { marker } }",
        "variables": {"id": "{resource_id}"},
        "field_path": "invoice.marker",
        "operation_name": "Invoice",
    }
    task = replace(
        _task(),
        task_id="task:graphql-auth",
        executor_capability=GraphQLAuthorizationDifferentialExecutor.CAPABILITY,
        payload=payload,
    )
    outcome = executor(task, _plan(task), authorization)
    assert outcome.verdicts[0].outcome is DifferentialOutcome.CONSISTENT
    assert len(calls) == 2 and {call[0] for call in calls} == {"POST"}
    assert all(call[1].endswith("/graphql") for call in calls)
    assert b'"id":"invoice-1"' in calls[0][3]


def test_cache_differential_requires_clean_cross_client_control():
    identity = _executor(expose_to_peer=True)
    executor = CacheDifferentialExecutor(
        identity.http,
        fixture_sets={"fixtures:http": _fixture_set()},
        credential_resolver=identity.credential_resolver,
        grant_verifier=identity.grant_verifier,
    )
    _, authorization = _authorization()
    task = replace(
        _task(),
        task_id="task:cache",
        executor_capability="dynamic:cache-key-differential",
        payload={
            "fixture_set_id": "fixtures:http",
            "dimension": "query_parameter",
            "marker": "AEGIS-CANARY-HTTP-1",
            "prime": {"path": "/prime", "fixture_kind": "owner"},
            "victim": {"path": "/victim", "fixture_kind": "foreign_same_role"},
            "negative_control": {"path": "/clean", "fixture_kind": "foreign_same_role"},
        },
    )
    outcome = executor(task, _plan(task), authorization)
    assert outcome.verdict.outcome is CacheOutcome.SHARED_INFLUENCE_CONFIRMED
    assert outcome.evidence.is_reproducible


def test_race_executor_uses_barrier_readbacks_and_detects_idempotency_failure():
    lock = Lock()
    effects = []

    def sender(method, url, _ip, headers, _body):
        if url.endswith("/state"):
            with lock:
                body = ('{"effects":%d}' % len(effects)).encode()
            return UpstreamResponse(200, {"content-type": "application/json"}, body)
        assert method == "POST" and url.endswith("/claim")
        assert headers["idempotency-key"] == "shared-test-key"
        with lock:
            effect = f"effect-{len(effects) + 1}"
            effects.append(effect)
        return UpstreamResponse(
            201, {"content-type": "application/json"},
            ('{"effect_id":"%s"}' % effect).encode(),
        )

    identity = _executor(expose_to_peer=False, sender_override=sender)
    executor = ScopedRaceIdempotencyExecutor(
        identity.http,
        fixture_sets={"fixtures:http": _fixture_set()},
        credential_resolver=identity.credential_resolver,
        grant_verifier=identity.grant_verifier,
        max_concurrency=2,
    )
    _, authorization = _authorization()
    task = replace(
        _task(),
        task_id="task:race",
        executor_capability="dynamic:idempotency-key-differential",
        idempotency_key="race-experiment-1",
        expected_requests=4,
        payload={
            "fixture_set_id": "fixtures:http",
            "fixture_kind": "owner",
            "attempts": 2,
            "method": "POST",
            "operation_path": "/claim",
            "state_path": "/state",
            "idempotency_key": "shared-test-key",
            "max_allowed_effects": 1,
            "resource": {
                "resource_id": "claim-1",
                "canary": "AEGIS-CANARY-HTTP-1",
                "synthetic": True,
            },
        },
    )
    outcome = executor(task, _plan(task), authorization)
    assert outcome.verdict.outcome is RaceOutcome.IDEMPOTENCY_FAILURE
    assert len(outcome.experiment.results) == 2
    assert outcome.experiment.before_state_digest != outcome.experiment.after_state_digest


def test_url_consumer_executor_requires_exact_private_oast_callback():
    principal = type("Principal", (), {"tenant_id": "tenant-a"})()
    oast = PrivateOastService(PrivateOastConfig(
        oast_domain="callbacks.aegis.test", is_production=True,
    ))
    registration = oast.register(
        principal,
        engagement_id="engagement-http",
        scan_id="mission-oast",
        reservation_id="reservation-oast",
    )

    def sender(_method, _url, _ip, _headers, body):
        probe_url = json.loads(body)["url"]
        host = probe_url.removeprefix("https://")
        oast.ingest(Interaction(
            protocol="https",
            host=host,
            remote_address="93.184.216.34",
            raw="controlled callback",
            observed_at=datetime.now(UTC),
        ))
        return UpstreamResponse(202, {"content-type": "application/json"}, b'{"queued":true}')

    identity = _executor(expose_to_peer=False, sender_override=sender)
    executor = ScopedURLConsumerExecutor(
        identity.http,
        fixture_sets={"fixtures:http": _fixture_set()},
        credential_resolver=identity.credential_resolver,
        grant_verifier=identity.grant_verifier,
        oast_service=oast,
        oast_principal=principal,
    )
    _, authorization = _authorization()
    task = replace(
        _task(),
        task_id="task:oast",
        executor_capability="dynamic:server-url-consumer",
        payload={
            "fixture_set_id": "fixtures:http",
            "oast_session_ref": registration.session_ref,
            "route": "/webhook",
            "parameter": "url",
            "method": "POST",
            "delivery": "synchronous",
        },
    )
    outcome = executor(task, _plan(task), authorization)
    assert outcome.verdict.outcome is URLConsumerOutcome.CALLBACK_CONFIRMED
    assert outcome.evidence.is_reproducible
    assert f"task:{task.task_id}" in outcome.verdict.evidence


def test_production_dispatcher_reports_real_and_unavailable_exact_capabilities():
    identity = _executor(expose_to_peer=False)
    graphql = _executor(expose_to_peer=False, graphql=True)
    cache = CacheDifferentialExecutor(
        identity.http, fixture_sets={}, credential_resolver=lambda _ref: {},
        grant_verifier=identity.grant_verifier,
    )
    race = ScopedRaceIdempotencyExecutor(
        identity.http, fixture_sets={}, credential_resolver=lambda _ref: {},
        grant_verifier=identity.grant_verifier,
    )
    executors = compose_production_executors((identity, graphql, cache, race))
    coverage = {row.capability: row.status for row in production_execution_coverage(executors)}
    assert coverage["dynamic:identity-object-differential"] == "REAL"
    assert coverage["dynamic:graphql-auth-differential"] == "REAL"
    assert coverage["dynamic:cache-key-differential"] == "REAL"
    assert coverage["dynamic:bounded-race-harness"] == "REAL"
    assert coverage["dynamic:websocket-state-differential"] == "UNAVAILABLE"


def test_runtime_retains_dynamic_evidence_and_missing_fixture_waits(tmp_path):
    executor = _executor(expose_to_peer=False)
    verifier, authorization = _authorization()
    with JarvisStateStore(tmp_path / "jarvis.db") as store:
        runtime = UniversalMissionRuntime(
            MissionScheduler(store),
            grant_verifier=verifier,
            executor_providers=(executor,),
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
