"""Concrete HTTP/API authorization differential mission executor."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from hashlib import sha256

from aegis.ai.agentic_os import AuthorizationEnvelope
from aegis.model.evidence import Canary, CanaryKind, EvidenceBundle, InteractionStep

from .execution_errors import MissionPrerequisiteError
from .identity_fixtures import ControlledIdentityFixtureSet, FixtureKind, FixtureProtocol
from .identity_intelligence import (
    AccessObservation,
    DifferentialVerdict,
    IdentityDifferentialOracle,
    SyntheticResource,
)
from .mission_scheduler import MissionPlan, MissionTask
from .scoped_http_executor import ScopedEgressHttpExecutor, ScopedHttpResponse

CredentialResolver = Callable[[str], Mapping[str, str]]


@dataclass(frozen=True, slots=True)
class HttpIdentityExecutionOutcome:
    observations: tuple[AccessObservation, ...]
    verdicts: tuple[DifferentialVerdict, ...]
    evidence: tuple[EvidenceBundle, ...]


class HttpIdentityDifferentialExecutor:
    """Compare controlled principals against an explicit authorization matrix.

    Fixtures and credential references are registered by the operator. Raw credentials are never
    accepted in mission payloads or retained in evidence.
    """

    CAPABILITIES = frozenset({
        "dynamic:identity-object-differential",
        "dynamic:identity-role-differential",
        "dynamic:identity-tenant-differential",
    })

    def __init__(
        self,
        http: ScopedEgressHttpExecutor,
        *,
        fixture_sets: Mapping[str, ControlledIdentityFixtureSet],
        credential_resolver: CredentialResolver,
        grant_verifier,
    ) -> None:
        self.http = http
        self.fixture_sets = dict(fixture_sets)
        self.credential_resolver = credential_resolver
        self.grant_verifier = grant_verifier
        self.oracle = IdentityDifferentialOracle()

    def __call__(
        self, task: MissionTask, plan: MissionPlan, authorization: AuthorizationEnvelope
    ) -> HttpIdentityExecutionOutcome:
        self._authorize(task, plan, authorization)
        payload = task.payload or {}
        fixture_id = str(payload.get("fixture_set_id") or "")
        fixtures = self.fixture_sets.get(fixture_id)
        if fixtures is None:
            raise MissionPrerequisiteError("controlled HTTP identity fixture set is not registered")
        if fixtures.scope_digest != plan.scope_digest:
            raise PermissionError("controlled fixture set is bound to a different mission scope")
        try:
            binding = fixtures.require_protocol(FixtureProtocol.HTTP)
            resource_doc = dict(payload["resource"])
            resource = SyntheticResource(
                resource_id=str(resource_doc["resource_id"]),
                owner_id=str(resource_doc["owner_id"]),
                tenant=str(resource_doc["tenant"]),
                canary=str(resource_doc["canary"]),
                synthetic=bool(resource_doc.get("synthetic", True)),
            )
            operation = str(payload["operation"])
        except (KeyError, TypeError, ValueError, LookupError) as exc:
            raise MissionPrerequisiteError(
                "HTTP differential requires a protocol binding, operation, and synthetic resource"
            ) from exc
        if not resource.synthetic or not resource.canary:
            raise MissionPrerequisiteError("HTTP differential requires a marked synthetic resource")
        method = str(payload.get("method") or "GET").upper()
        body_template = str(payload.get("body_template") or "")
        url = binding.endpoint.replace("{resource_id}", resource.resource_id)
        body = (
            body_template.replace("{resource_id}", resource.resource_id)
            .replace("{canary}", resource.canary)
            .encode("utf-8")
        )
        owner_fixture = fixtures.fixtures.get(FixtureKind.OWNER)
        if owner_fixture is None:
            raise MissionPrerequisiteError("HTTP differential requires an owner control")
        control_response = self._send(owner_fixture.credential.reference, method, url, body, authorization)
        control = self._observation(
            owner_fixture.principal(), resource, operation, control_response,
            evidence=(f"binding:{binding.endpoint}", *binding.evidence),
        )
        matrix = fixtures.authorization_matrix(resource)
        observations = [control]
        verdicts = []
        bundles = []
        for kind, fixture in sorted(fixtures.fixtures.items(), key=lambda item: item[0].value):
            if kind is FixtureKind.OWNER:
                continue
            probe_response = self._send(
                fixture.credential.reference, method, url, body, authorization
            )
            probe = self._observation(
                fixture.principal(), resource, operation, probe_response,
                evidence=(f"binding:{binding.endpoint}", *binding.evidence),
            )
            verdict = self.oracle.evaluate(control, probe, matrix)
            bundle = self._evidence(control, probe, verdict, resource)
            observations.append(probe)
            verdicts.append(verdict)
            bundles.append(bundle)
        if not verdicts:
            raise MissionPrerequisiteError("HTTP differential requires a distinct controlled probe")
        return HttpIdentityExecutionOutcome(
            tuple(observations), tuple(verdicts), tuple(bundles)
        )

    def _authorize(
        self, task: MissionTask, plan: MissionPlan, authorization: AuthorizationEnvelope
    ) -> None:
        if task.executor_capability not in self.CAPABILITIES:
            raise PermissionError("HTTP identity executor received an unsupported capability")
        grant = authorization.grant
        if (
            grant is None
            or authorization.scope_digest != plan.scope_digest
            or grant.scope_digest != plan.scope_digest
            or not grant.verify(self.grant_verifier)
            or not grant.network_allowed
            or not grant.state_change_allowed
            or not grant.human_approval
        ):
            raise PermissionError("HTTP differential requires a verified state-change grant")

    def _send(
        self, reference: str, method: str, url: str, body: bytes,
        authorization: AuthorizationEnvelope,
    ) -> ScopedHttpResponse:
        try:
            headers = dict(self.credential_resolver(reference))
        except Exception as exc:
            raise MissionPrerequisiteError(
                f"operator credential reference could not be resolved: {reference}"
            ) from exc
        if not headers:
            raise MissionPrerequisiteError(
                f"operator credential reference resolved to no headers: {reference}"
            )
        return self.http.request(
            method, url, authorization=authorization, headers=headers, body=body
        )

    @staticmethod
    def _observation(
        principal, resource: SyntheticResource, operation: str,
        response: ScopedHttpResponse, *, evidence: tuple[str, ...],
    ) -> AccessObservation:
        digest = sha256(response.body).hexdigest()
        marker = resource.canary.encode("utf-8")
        return AccessObservation(
            principal=principal,
            resource=resource,
            operation=operation,
            status_code=response.status_code,
            response_digest=digest,
            returned_markers=(resource.canary,) if marker in response.body else (),
            correlation_id=f"http:{digest[:20]}",
            evidence=tuple(dict.fromkeys((*evidence, f"response-sha256:{digest}"))),
        )

    @staticmethod
    def _evidence(
        control: AccessObservation,
        probe: AccessObservation,
        verdict: DifferentialVerdict,
        resource: SyntheticResource,
    ) -> EvidenceBundle:
        return EvidenceBundle(
            steps=[
                InteractionStep(
                    summary="controlled owner authorization control",
                    request=f"principal={control.principal.principal_id}; operation={control.operation}",
                    response=f"status={control.status_code}; sha256={control.response_digest}",
                ),
                InteractionStep(
                    summary=f"controlled {verdict.dimension} negative control",
                    request=f"principal={probe.principal.principal_id}; operation={probe.operation}",
                    response=f"status={probe.status_code}; sha256={probe.response_digest}",
                ),
            ],
            canary=Canary(
                kind=CanaryKind.SEEDED_RECORD,
                value=resource.canary,
                note="operator-controlled synthetic resource marker",
            ),
            observed=verdict.reason,
            expected="behavior must match the operator-supplied authorization matrix",
            replay_ref=verdict.verdict_id,
            confidence=verdict.confidence,
            artifacts=list(verdict.evidence),
        )

    def runtime_executors(self) -> dict[str, object]:
        return {capability: self for capability in self.CAPABILITIES}


__all__ = ["HttpIdentityDifferentialExecutor", "HttpIdentityExecutionOutcome"]
