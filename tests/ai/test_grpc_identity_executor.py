from __future__ import annotations

import base64
import time
from concurrent import futures
from dataclasses import replace

import grpc
import pytest
from fastapi.testclient import TestClient
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

from aegis.ai.agentic_os import (
    AuthorizationEnvelope,
    Budget,
    mint_execution_grant,
    process_grant_verifier,
)
from aegis.ai.jarvis.grpc_identity_executor import (
    POLICY_ACTION,
    GrpcAuthorizationDifferentialExecutor,
    GrpcMethodDefinition,
    ScopedGrpcTransport,
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
from aegis.egress.app import EgressServiceConfig, create_egress_app
from aegis.egress.auth import EgressClaims, issue_token
from aegis.egress.grpc_transport import (
    GrpcUnaryRequest,
    GrpcUnaryResponse,
    default_grpc_unary_sender,
)
from aegis.gateway import NetworkProfile

SCOPE = "scope:grpc"
SECRET = "grpc-test-signing-secret-that-is-long-enough"
SERVICE_METHOD = "/lab.InvoiceService/GetInvoice"


def _schema():
    document = descriptor_pb2.FileDescriptorProto(
        name="invoice.proto", package="lab", syntax="proto3",
    )
    request = document.message_type.add(name="InvoiceRequest")
    request.field.add(
        name="resource_id", number=1,
        type=descriptor_pb2.FieldDescriptorProto.TYPE_STRING,
        label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL,
    )
    response = document.message_type.add(name="InvoiceResponse")
    response.field.add(
        name="marker", number=1,
        type=descriptor_pb2.FieldDescriptorProto.TYPE_STRING,
        label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL,
    )
    service = document.service.add(name="InvoiceService")
    method = service.method.add(
        name="GetInvoice", input_type=".lab.InvoiceRequest", output_type=".lab.InvoiceResponse",
    )
    assert method.name == "GetInvoice"
    descriptor_set = descriptor_pb2.FileDescriptorSet()
    descriptor_set.file.add().CopyFrom(document)
    pool = descriptor_pool.DescriptorPool()
    pool.Add(document)
    request_class = message_factory.GetMessageClass(pool.FindMessageTypeByName("lab.InvoiceRequest"))
    response_class = message_factory.GetMessageClass(pool.FindMessageTypeByName("lab.InvoiceResponse"))
    return descriptor_set.SerializeToString(), request_class, response_class


def _authorization(*, requests=2):
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


def _definition(port=443):
    descriptor, _, _ = _schema()
    return GrpcMethodDefinition(
        "invoice.get",
        SCOPE,
        f"http://grpc.example.test:{port}{SERVICE_METHOD}",
        SERVICE_METHOD,
        "lab.InvoiceRequest",
        "lab.InvoiceResponse",
        descriptor,
        ("operator-schema:invoice.proto", "scope-confirmed:grpc.example.test"),
    )


def _fixtures(definition):
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
        bindings=(ProtocolBinding(
            FixtureProtocol.GRPC, definition.endpoint, ("scope-confirmed:grpc.example.test",),
        ),),
        expectations=(FixtureExpectation(
            "invoice.read", FixtureKind.FOREIGN_SAME_ROLE, "invoice-1",
            ExpectedAccess.DENY, ("policy:owner-only",),
        ),),
    )


def _task():
    return MissionTask(
        "task:grpc", "authorization", "controlled unary gRPC differential",
        executor_capability=GrpcAuthorizationDifferentialExecutor.CAPABILITY,
        risk="controlled_state_change", expected_requests=2,
        payload={
            "fixture_set_id": "fixtures:grpc",
            "grpc_method_id": "invoice.get",
            "operation": "invoice.read",
            "request_json": {"resource_id": "{resource_id}"},
            "resource": {
                "resource_id": "invoice-1", "owner_id": "owner", "tenant": "tenant-a",
                "canary": "AEGIS-GRPC-CANARY-1", "synthetic": True,
            },
        },
    )


def _plan(task=None):
    return MissionPlan("mission:grpc", SCOPE, "verify gRPC authorization", (task or _task(),))


def _executor(*, expose_to_peer=False, registry=True, observed=None):
    definition = _definition()

    def grpc_sender(url, pinned_ip, request, metadata):
        if observed is not None:
            observed.append((url, pinned_ip, request.service_method, dict(metadata)))
        identity = metadata["authorization"].removeprefix("Bearer ")
        if identity == "owner" or expose_to_peer:
            return GrpcUnaryResponse(
                status="OK", response_json={"marker": "AEGIS-GRPC-CANARY-1"},
            )
        return GrpcUnaryResponse(status="PERMISSION_DENIED", details="controlled denial")

    app = create_egress_app(
        EgressServiceConfig(SECRET),
        resolver=lambda _host: ["93.184.216.34"],
        grpc_unary_sender=grpc_sender,
    )
    client = TestClient(app)

    def token_issuer(action, destination, authorization):
        assert action == POLICY_ACTION
        now = int(time.time())
        return issue_token(EgressClaims(
            tenant_id="tenant-a", engagement_id="engagement-grpc",
            profile=NetworkProfile.TARGET_MUTATION.value,
            method="POST", destination=destination, issued_at=now, expires_at=now + 60,
            budget_id="budget-grpc", request_limit=authorization.budget.max_requests,
            scope=["grpc.example.test"], allowed_methods=["POST"],
        ), SECRET, now=now)

    verifier, _ = _authorization()
    transport = ScopedGrpcTransport(
        "https://egress.internal", token_issuer=token_issuer,
        grant_verifier=verifier, client=client,
    )
    return GrpcAuthorizationDifferentialExecutor(
        transport,
        fixture_sets={"fixtures:grpc": _fixtures(definition)},
        method_registry=({"invoice.get": definition} if registry else {}),
        credential_resolver=lambda reference: {
            "authorization": f"Bearer {reference.rsplit('/', 1)[-1]}",
        },
        grant_verifier=verifier,
    )


def test_real_local_synthetic_grpc_target_uses_registered_descriptor():
    descriptor, request_class, response_class = _schema()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))

    def get_invoice(request, context):
        metadata = dict(context.invocation_metadata())
        if metadata.get("authorization") != "Bearer owner":
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "controlled denial")
        return response_class(marker="AEGIS-GRPC-CANARY-LAB")

    handler = grpc.unary_unary_rpc_method_handler(
        get_invoice,
        request_deserializer=request_class.FromString,
        response_serializer=lambda message: message.SerializeToString(),
    )
    server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler(
        "lab.InvoiceService", {"GetInvoice": handler},
    ),))
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    request = GrpcUnaryRequest(
        url=f"http://grpc.example.test:{port}{SERVICE_METHOD}",
        service_method=SERVICE_METHOD,
        request_type="lab.InvoiceRequest",
        response_type="lab.InvoiceResponse",
        descriptor_set_base64=base64.b64encode(descriptor).decode("ascii"),
        request_json={"resource_id": "invoice-1"},
        metadata={"authorization": "Bearer owner"},
    )
    try:
        owner = default_grpc_unary_sender(
            request.url, "127.0.0.1", request, {"authorization": "Bearer owner"},
        )
        peer = default_grpc_unary_sender(
            request.url, "127.0.0.1", request, {"authorization": "Bearer peer"},
        )
    finally:
        server.stop(grace=0).wait()
    assert owner.status == "OK"
    assert owner.response_json == {"marker": "AEGIS-GRPC-CANARY-LAB"}
    assert peer.status == "PERMISSION_DENIED"


def test_grpc_negative_control_and_scope_pinned_metadata_are_canonical():
    observed = []
    executor = _executor(observed=observed)
    _, authorization = _authorization()
    outcome = executor(_task(), _plan(), authorization)
    assert outcome.verdicts[0].outcome is DifferentialOutcome.CONSISTENT
    assert outcome.observations[0].returned_markers == ("AEGIS-GRPC-CANARY-1",)
    assert outcome.observations[1].status_code == 403
    assert len(observed) == 2
    assert all(row[1] == "93.184.216.34" and row[2] == SERVICE_METHOD for row in observed)
    serialized = outcome.evidence[0].model_dump_json()
    assert "Bearer owner" not in serialized and "Bearer peer" not in serialized


def test_grpc_cross_identity_canary_is_a_positive_violation():
    executor = _executor(expose_to_peer=True)
    _, authorization = _authorization()
    outcome = executor(_task(), _plan(), authorization)
    assert outcome.verdicts[0].outcome is DifferentialOutcome.VIOLATION
    assert outcome.evidence[0].is_reproducible


def test_grpc_missing_schema_budget_and_grant_fail_closed():
    executor = _executor(registry=False)
    _, authorization = _authorization()
    with pytest.raises(RuntimeError, match="registered method schema"):
        executor(_task(), _plan(), authorization)

    executor = _executor()
    _, one_request = _authorization(requests=1)
    with pytest.raises(RuntimeError, match="request budget exhausted"):
        executor(_task(), _plan(), one_request)

    executor = _executor()
    with pytest.raises(PermissionError, match="exact verified grant"):
        executor(
            _task(), _plan(), AuthorizationEnvelope(scope_digest=SCOPE, budget=authorization.budget),
        )


def test_grpc_binding_and_exact_capability_are_enforced():
    executor = _executor()
    _, authorization = _authorization()
    wrong = replace(_task(), executor_capability="dynamic:graphql-auth-differential")
    with pytest.raises(PermissionError, match="exact verified grant"):
        executor(wrong, _plan(wrong), authorization)
    original = executor.method_registry["invoice.get"]
    executor.method_registry["invoice.get"] = replace(
        original, endpoint=f"http://other.example.test{SERVICE_METHOD}",
    )
    with pytest.raises(PermissionError, match="binding does not match"):
        executor(_task(), _plan(), authorization)


def test_grpc_executor_registers_as_real_production_capability():
    executor = _executor()
    registered = compose_production_executors((executor,))
    coverage = {row.capability: row.status for row in production_execution_coverage(registered)}
    assert coverage[GrpcAuthorizationDifferentialExecutor.CAPABILITY] == "REAL"
