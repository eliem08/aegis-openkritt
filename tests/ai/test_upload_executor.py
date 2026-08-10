from __future__ import annotations

import json
import time
from datetime import UTC, datetime

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
from aegis.ai.jarvis.mission_scheduler import MissionPlan, MissionTask
from aegis.ai.jarvis.scoped_http_executor import ScopedEgressHttpExecutor
from aegis.ai.jarvis.upload_executor import ScopedUploadWorkflowExecutor
from aegis.egress.app import EgressServiceConfig, UpstreamResponse, create_egress_app
from aegis.egress.auth import EgressClaims, issue_token
from aegis.gateway import NetworkProfile
from aegis.oast.models import Interaction
from aegis.oast.service import PrivateOastConfig, PrivateOastService

SCOPE = "scope:upload"
SECRET = "upload-test-signing-secret-that-is-long-enough"


def _authorization(requests=5):
    verifier = process_grant_verifier()
    budget = Budget(max_cost_usd=1, max_requests=requests, max_human_minutes=2)
    grant = mint_execution_grant(
        type("AllowedPolicyDecision", (), {"allowed": True})(),
        scope_digest=SCOPE, budget=budget, verifier=verifier,
        network=True, state_change=True, human_approval=True,
    )
    return verifier, AuthorizationEnvelope(scope_digest=SCOPE, budget=budget, grant=grant)


def _fixtures():
    def identity(kind, name):
        return ControlledIdentityFixture(
            kind, name, "member", "tenant-a",
            CredentialReference(f"vault://identities/{name}", SCOPE, (f"operator:{name}",)),
        )
    return ControlledIdentityFixtureSet(
        scope_digest=SCOPE,
        fixtures=(identity(FixtureKind.OWNER, "owner"),
                  identity(FixtureKind.FOREIGN_SAME_ROLE, "peer")),
        bindings=(ProtocolBinding(FixtureProtocol.HTTP, "https://api.example.test/",
                                  ("scope-confirmed:api.example.test",)),),
    )


def _task(session_ref, **overrides):
    payload = {
        "fixture_set_id": "fixtures:upload", "oast_session_ref": session_ref,
        "canary": "AEGIS-UPLOAD-CANARY-1", "filename": "aegis-fixture.txt",
        "upload_path": "/uploads", "status_path": "/uploads/{upload_id}/status",
        "retrieval_path": "/uploads/{upload_id}/content",
        "renderer_path": "/uploads/{upload_id}/render",
    }
    payload.update(overrides)
    return MissionTask(
        "task:upload", "upload", "safe synthetic upload workflow",
        executor_capability=ScopedUploadWorkflowExecutor.CAPABILITY,
        risk="controlled_state_change", expected_requests=5, payload=payload,
    )


def _executor(*, peer_exposed=False, oast_fetch=False, renderer_ok=True):
    principal = type("Principal", (), {"tenant_id": "tenant-a"})()
    oast = PrivateOastService(PrivateOastConfig(
        oast_domain="callbacks.aegis.test", is_production=True,
    ))
    registration = oast.register(
        principal, engagement_id="eng-upload", scan_id="mission-upload",
        reservation_id="reservation-upload",
    )

    def sender(method, url, _ip, headers, body):
        identity = headers.get("authorization", "").removeprefix("Bearer ")
        if method == "POST" and url.endswith("/uploads"):
            document = json.loads(body)
            assert document["content_type"] == "text/plain"
            if oast_fetch:
                host = document["metadata_url"].removeprefix("https://")
                oast.ingest(Interaction("https", host, "93.184.216.34",
                                        "controlled callback", datetime.now(UTC)))
            return UpstreamResponse(201, {}, b'{"upload_id":"upload-1"}')
        if url.endswith("/status"):
            return UpstreamResponse(200, {}, json.dumps({
                "storage_state": "stored", "worker_state": "processed",
                "renderer_state": "rendered" if renderer_ok else "failed",
            }).encode())
        if url.endswith("/content"):
            if identity == "owner" or peer_exposed:
                return UpstreamResponse(200, {}, b"AEGIS-UPLOAD-CANARY-1")
            return UpstreamResponse(403, {}, b"denied")
        if url.endswith("/render"):
            return UpstreamResponse(200, {},
                                    b"AEGIS-UPLOAD-CANARY-1" if renderer_ok else b"failed")
        raise AssertionError(url)

    app = create_egress_app(
        EgressServiceConfig(SECRET), resolver=lambda _host: ["93.184.216.34"], sender=sender,
    )
    client = TestClient(app)

    def token_issuer(_action, method, destination, authorization):
        now = int(time.time())
        return issue_token(EgressClaims(
            tenant_id="tenant-a", engagement_id="eng-upload",
            profile=NetworkProfile.TARGET_MUTATION.value,
            method=method, destination=destination, issued_at=now, expires_at=now + 60,
            budget_id="budget-upload", request_limit=authorization.budget.max_requests,
            scope=["api.example.test"], allowed_methods=[method],
        ), SECRET, now=now)

    verifier, _ = _authorization()
    http = ScopedEgressHttpExecutor(
        "https://egress.internal", token_issuer=token_issuer,
        grant_verifier=verifier, client=client,
    )
    executor = ScopedUploadWorkflowExecutor(
        http, fixture_sets={"fixtures:upload": _fixtures()},
        credential_resolver=lambda ref: {"authorization": "Bearer " + ref.rsplit("/", 1)[-1]},
        grant_verifier=verifier, oast_service=oast, oast_principal=principal,
    )
    return executor, registration.session_ref


def test_upload_workflow_clean_negative_controls_cover_all_stages():
    executor, session = _executor()
    task = _task(session)
    _, authorization = _authorization()
    outcome = executor(task, MissionPlan("mission:upload", SCOPE, "upload", (task,)), authorization)
    assert not outcome.verdict.cross_user_access
    assert not outcome.verdict.unexpected_server_fetch
    assert not outcome.verdict.worker_state_mismatch
    assert outcome.evidence.is_reproducible


@pytest.mark.parametrize(
    ("kwargs", "field"),
    [
        ({"peer_exposed": True}, "cross_user_access"),
        ({"oast_fetch": True}, "unexpected_server_fetch"),
        ({"renderer_ok": False}, "worker_state_mismatch"),
    ],
)
def test_upload_workflow_detects_cross_user_oast_and_worker_violations(kwargs, field):
    executor, session = _executor(**kwargs)
    task = _task(session)
    _, authorization = _authorization()
    outcome = executor(task, MissionPlan("mission:upload", SCOPE, "upload", (task,)), authorization)
    assert getattr(outcome.verdict, field)
    assert outcome.evidence.observed == "upload workflow violation observed"


def test_upload_rejects_unsafe_file_and_exhausted_budget():
    executor, session = _executor()
    unsafe = _task(session, filename="payload.svg")
    _, authorization = _authorization()
    with pytest.raises(RuntimeError, match="safe text allowlist"):
        executor(unsafe, MissionPlan("mission:unsafe", SCOPE, "upload", (unsafe,)), authorization)

    executor, session = _executor()
    task = _task(session)
    _, too_small = _authorization(requests=4)
    with pytest.raises(RuntimeError, match="request budget exhausted"):
        executor(task, MissionPlan("mission:budget", SCOPE, "upload", (task,)), too_small)
