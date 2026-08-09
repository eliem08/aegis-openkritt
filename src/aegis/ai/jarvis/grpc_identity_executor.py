"""Known-schema unary gRPC authorization differential over scoped egress."""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from hashlib import sha256
from threading import Lock
from urllib.parse import urlsplit

import httpx

from aegis.ai.agentic_os import AuthorizationEnvelope
from aegis.model.evidence import Canary, CanaryKind, EvidenceBundle, InteractionStep

from .execution_errors import MissionBackendUnavailableError, MissionPrerequisiteError
from .identity_fixtures import ControlledIdentityFixtureSet, FixtureKind, FixtureProtocol
from .identity_intelligence import (
    AccessObservation,
    DifferentialVerdict,
    IdentityDifferentialOracle,
    SyntheticResource,
)
from .mission_scheduler import MissionPlan, MissionTask

POLICY_ACTION = "hunter.grpc.execute"
GrpcTokenIssuer = Callable[[str, str, AuthorizationEnvelope], str]
CredentialResolver = Callable[[str], Mapping[str, str]]


@dataclass(frozen=True, slots=True)
class GrpcMethodDefinition:
    method_id: str
    scope_digest: str
    endpoint: str
    service_method: str
    request_type: str
    response_type: str
    descriptor_set: bytes
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        parts = urlsplit(self.endpoint)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("gRPC method endpoint must be an HTTP(S) authority")
        if not self.service_method.startswith("/") or parts.path != self.service_method:
            raise ValueError("gRPC service method must exactly match the endpoint path")
        if not all((self.method_id, self.scope_digest, self.request_type, self.response_type)):
            raise ValueError("gRPC method definition is incomplete")
        if not self.descriptor_set or not self.evidence:
            raise ValueError("gRPC method requires an operator-registered schema and evidence")


@dataclass(frozen=True, slots=True)
class ScopedGrpcResponse:
    status: str
    details: str
    response_json: Mapping[str, object] | None


class ScopedGrpcTransport:
    """Execute unary calls through the grant-bound scoped egress sidecar."""

    def __init__(
        self,
        endpoint: str,
        *,
        token_issuer: GrpcTokenIssuer,
        grant_verifier,
        max_requests: int = 12,
        max_requests_per_second: int = 8,
        timeout_seconds: float = 8.0,
        client=None,
    ) -> None:
        parts = urlsplit(endpoint)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("scoped gRPC egress endpoint must be HTTP(S)")
        if max_requests_per_second <= 0:
            raise ValueError("gRPC rate budget must be positive")
        self.endpoint = endpoint.rstrip("/") + "/v1/grpc/unary"
        self.token_issuer = token_issuer
        self.grant_verifier = grant_verifier
        self.max_requests = max_requests
        self.max_requests_per_second = max_requests_per_second
        self.timeout_seconds = timeout_seconds
        self.client = client
        self.requests = 0
        self._budget_lock = Lock()
        self._window_started = time.monotonic()
        self._window_requests = 0

    def unary(
        self,
        definition: GrpcMethodDefinition,
        *,
        authorization: AuthorizationEnvelope,
        metadata: Mapping[str, str],
        request_json: Mapping[str, object],
    ) -> ScopedGrpcResponse:
        grant = authorization.grant
        if (
            grant is None
            or grant.scope_digest != authorization.scope_digest
            or not grant.verify(self.grant_verifier)
            or not grant.network_allowed
            or not grant.state_change_allowed
        ):
            raise PermissionError("gRPC execution requires a verified state-change grant")
        authorized_limit = min(
            self.max_requests,
            max(0, authorization.budget.max_requests),
            max(0, grant.budget.max_requests),
        )
        with self._budget_lock:
            now = time.monotonic()
            if now - self._window_started >= 1.0:
                self._window_started = now
                self._window_requests = 0
            if self.requests >= authorized_limit:
                raise RuntimeError("gRPC execution request budget exhausted")
            if self._window_requests >= self.max_requests_per_second:
                raise RuntimeError("gRPC execution rate budget exhausted")
            self.requests += 1
            self._window_requests += 1
        token = self.token_issuer(POLICY_ACTION, definition.endpoint, authorization)
        if not token:
            raise PermissionError("egress token issuer refused the gRPC destination")
        payload = {
            "url": definition.endpoint,
            "service_method": definition.service_method,
            "request_type": definition.request_type,
            "response_type": definition.response_type,
            "descriptor_set_base64": base64.b64encode(definition.descriptor_set).decode("ascii"),
            "request_json": dict(request_json),
            "metadata": dict(metadata),
            "timeout_seconds": min(self.timeout_seconds, 30.0),
        }
        try:
            if self.client is not None:
                response = self.client.post(
                    self.endpoint,
                    json=payload,
                    headers={"authorization": f"Bearer {token}"},
                    timeout=self.timeout_seconds + 1,
                )
            else:
                with httpx.Client(timeout=self.timeout_seconds + 1, trust_env=False) as client:
                    response = client.post(
                        self.endpoint,
                        json=payload,
                        headers={"authorization": f"Bearer {token}"},
                    )
            response.raise_for_status()
            document = response.json()
            body = document.get("response_json")
            if body is not None and not isinstance(body, Mapping):
                raise ValueError("gRPC response_json must be an object")
            return ScopedGrpcResponse(
                status=str(document["status"]),
                details=str(document.get("details") or "")[:512],
                response_json=dict(body) if body is not None else None,
            )
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
            raise MissionBackendUnavailableError(
                f"scoped gRPC egress failed to produce a valid response: {exc}"
            ) from exc


@dataclass(frozen=True, slots=True)
class GrpcIdentityExecutionOutcome:
    observations: tuple[AccessObservation, ...]
    verdicts: tuple[DifferentialVerdict, ...]
    responses: tuple[ScopedGrpcResponse, ...]
    evidence: tuple[EvidenceBundle, ...]


class GrpcAuthorizationDifferentialExecutor:
    CAPABILITY = "dynamic:grpc-auth-differential"

    def __init__(
        self,
        transport: ScopedGrpcTransport,
        *,
        fixture_sets: Mapping[str, ControlledIdentityFixtureSet],
        method_registry: Mapping[str, GrpcMethodDefinition],
        credential_resolver: CredentialResolver,
        grant_verifier,
    ) -> None:
        self.transport = transport
        self.fixture_sets = dict(fixture_sets)
        self.method_registry = dict(method_registry)
        self.credential_resolver = credential_resolver
        self.grant_verifier = grant_verifier
        self.oracle = IdentityDifferentialOracle()

    def __call__(
        self, task: MissionTask, plan: MissionPlan, authorization: AuthorizationEnvelope,
    ) -> GrpcIdentityExecutionOutcome:
        self._authorize(task, plan, authorization)
        payload = task.payload or {}
        fixtures = self.fixture_sets.get(str(payload.get("fixture_set_id") or ""))
        definition = self.method_registry.get(str(payload.get("grpc_method_id") or ""))
        if fixtures is None or definition is None:
            raise MissionPrerequisiteError(
                "controlled gRPC fixtures and an operator-registered method schema are required"
            )
        if fixtures.scope_digest != plan.scope_digest or definition.scope_digest != plan.scope_digest:
            raise PermissionError("gRPC fixtures or schema are bound to a different mission scope")
        try:
            binding = fixtures.require_protocol(FixtureProtocol.GRPC)
            resource_doc = dict(payload["resource"])
            resource = SyntheticResource(
                resource_id=str(resource_doc["resource_id"]),
                owner_id=str(resource_doc["owner_id"]),
                tenant=str(resource_doc["tenant"]),
                canary=str(resource_doc["canary"]),
                synthetic=bool(resource_doc.get("synthetic", True)),
            )
            operation = str(payload["operation"])
            request_template = dict(payload["request_json"])
        except (KeyError, TypeError, ValueError, LookupError) as exc:
            raise MissionPrerequisiteError(
                "gRPC differential requires a binding, synthetic resource, and request object"
            ) from exc
        if binding.endpoint != definition.endpoint:
            raise PermissionError("gRPC fixture binding does not match the registered method endpoint")
        if not resource.synthetic or not resource.canary:
            raise MissionPrerequisiteError("gRPC differential requires a synthetic canary resource")
        owner = fixtures.fixtures.get(FixtureKind.OWNER)
        probes = [
            fixture for kind, fixture in sorted(
                fixtures.fixtures.items(), key=lambda item: item[0].value,
            ) if kind is not FixtureKind.OWNER
        ]
        if owner is None or not probes:
            raise MissionPrerequisiteError("gRPC differential requires owner and probe identities")
        observations = []
        responses = []
        for fixture in (owner, *probes):
            try:
                metadata = dict(self.credential_resolver(fixture.credential.reference))
            except Exception as exc:
                raise MissionPrerequisiteError(
                    f"operator credential reference could not be resolved: {fixture.credential.reference}"
                ) from exc
            if not metadata:
                raise MissionPrerequisiteError("gRPC credential resolved to no identity metadata")
            response = self.transport.unary(
                definition,
                authorization=authorization,
                metadata=metadata,
                request_json=self._substitute(
                    request_template, resource, fixture.principal_id,
                ),
            )
            responses.append(response)
            observations.append(self._observation(
                fixture.principal(), resource, operation, response,
                evidence=(
                    f"binding:{binding.endpoint}", *binding.evidence, *definition.evidence,
                    f"schema-sha256:{sha256(definition.descriptor_set).hexdigest()}",
                ),
            ))
        matrix = fixtures.authorization_matrix(resource)
        control = observations[0]
        verdicts = tuple(self.oracle.evaluate(control, probe, matrix) for probe in observations[1:])
        evidence = tuple(
            self._evidence(control, probe, verdict, resource, definition, responses[0], responses[i + 1])
            for i, (probe, verdict) in enumerate(zip(observations[1:], verdicts, strict=True))
        )
        return GrpcIdentityExecutionOutcome(
            tuple(observations), verdicts, tuple(responses), evidence,
        )

    def _authorize(self, task, plan, authorization):
        grant = authorization.grant
        if (
            task.executor_capability != self.CAPABILITY
            or grant is None
            or authorization.scope_digest != plan.scope_digest
            or grant.scope_digest != plan.scope_digest
            or not grant.verify(self.grant_verifier)
            or not grant.network_allowed
            or not grant.state_change_allowed
            or not grant.human_approval
        ):
            raise PermissionError("gRPC differential requires an exact verified grant")

    @classmethod
    def _substitute(cls, value, resource, principal_id):
        if isinstance(value, str):
            return (value.replace("{resource_id}", resource.resource_id)
                    .replace("{canary}", resource.canary)
                    .replace("{principal_id}", principal_id))
        if isinstance(value, Mapping):
            return {str(key): cls._substitute(item, resource, principal_id)
                    for key, item in value.items()}
        if isinstance(value, list):
            return [cls._substitute(item, resource, principal_id) for item in value]
        return value

    @staticmethod
    def _observation(principal, resource, operation, response, *, evidence):
        raw = json.dumps(response.response_json or {}, sort_keys=True, separators=(",", ":"))
        digest = sha256(raw.encode("utf-8")).hexdigest()
        returned = (resource.canary,) if resource.canary in raw else ()
        if response.status == "OK":
            status_code = 200
        elif response.status in {"PERMISSION_DENIED", "UNAUTHENTICATED", "NOT_FOUND"}:
            status_code = 403
        else:
            status_code = 500
        return AccessObservation(
            principal=principal,
            resource=resource,
            operation=operation,
            status_code=status_code,
            response_digest=digest,
            returned_markers=returned,
            correlation_id=f"grpc:{digest[:20]}",
            evidence=tuple(dict.fromkeys((*evidence, f"grpc-status:{response.status}",
                                          f"response-sha256:{digest}"))),
        )

    @staticmethod
    def _evidence(control, probe, verdict, resource, definition, control_response, probe_response):
        return EvidenceBundle(
            steps=[
                InteractionStep(
                    summary="controlled owner unary gRPC call",
                    request=f"method={definition.service_method}; principal={control.principal.principal_id}",
                    response=f"status={control_response.status}; sha256={control.response_digest}",
                ),
                InteractionStep(
                    summary="controlled cross-identity unary gRPC call",
                    request=f"method={definition.service_method}; principal={probe.principal.principal_id}",
                    response=f"status={probe_response.status}; sha256={probe.response_digest}",
                ),
            ],
            canary=Canary(
                kind=CanaryKind.SEEDED_RECORD,
                value=resource.canary,
                note="operator-controlled gRPC resource marker",
            ),
            observed=verdict.reason,
            expected="unary resource access must match the authorization matrix",
            replay_ref=verdict.verdict_id,
            confidence=verdict.confidence,
            artifacts=list(verdict.evidence),
        )

    def runtime_executors(self) -> dict[str, object]:
        return {self.CAPABILITY: self}


__all__ = [
    "POLICY_ACTION", "GrpcAuthorizationDifferentialExecutor", "GrpcIdentityExecutionOutcome",
    "GrpcMethodDefinition", "ScopedGrpcResponse", "ScopedGrpcTransport",
]
