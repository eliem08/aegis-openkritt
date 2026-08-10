"""Real bounded race/idempotency execution over scoped HTTP egress."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from urllib.parse import urljoin

from aegis.ai.agentic_os import AuthorizationEnvelope
from aegis.model.evidence import Canary, CanaryKind, EvidenceBundle, InteractionStep

from .execution_errors import MissionPrerequisiteError
from .identity_fixtures import ControlledIdentityFixtureSet, FixtureKind, FixtureProtocol
from .identity_intelligence import (
    AccessObservation,
    ErrorStateVerifier,
    StateVerification,
    SyntheticResource,
)
from .mission_scheduler import MissionPlan, MissionTask
from .race_intelligence import (
    AttemptResult,
    BoundedConcurrencyHarness,
    RaceConditionAgent,
    RaceExperiment,
    RaceVerdict,
)
from .scoped_http_executor import ScopedEgressHttpExecutor


@dataclass(frozen=True, slots=True)
class RaceExecutionOutcome:
    experiment: RaceExperiment
    verdict: RaceVerdict
    state_verifications: tuple[StateVerification, ...]
    evidence: EvidenceBundle


class ScopedRaceIdempotencyExecutor:
    CAPABILITIES = frozenset({
        "dynamic:bounded-race-harness",
        "dynamic:idempotency-key-differential",
        "dynamic:retry-state-verifier",
    })

    def __init__(self, http: ScopedEgressHttpExecutor, *, fixture_sets,
                 credential_resolver, grant_verifier, max_concurrency: int = 4) -> None:
        self.http = http
        self.fixture_sets: Mapping[str, ControlledIdentityFixtureSet] = dict(fixture_sets)
        self.credential_resolver = credential_resolver
        self.grant_verifier = grant_verifier
        self.harness = BoundedConcurrencyHarness(
            grant_verifier=grant_verifier, max_concurrency=max_concurrency
        )
        self.agent = RaceConditionAgent()
        self.state_verifier = ErrorStateVerifier()

    def __call__(self, task: MissionTask, plan: MissionPlan,
                 authorization: AuthorizationEnvelope) -> RaceExecutionOutcome:
        self._authorize(task, plan, authorization)
        payload = task.payload or {}
        fixtures = self.fixture_sets.get(str(payload.get("fixture_set_id") or ""))
        if fixtures is None:
            raise MissionPrerequisiteError("race fixture set is not registered")
        if fixtures.scope_digest != plan.scope_digest:
            raise PermissionError("race fixtures are bound to a different mission scope")
        try:
            binding = fixtures.require_protocol(FixtureProtocol.HTTP)
            fixture = fixtures.fixtures[FixtureKind(str(payload.get("fixture_kind") or "owner"))]
            headers = dict(self.credential_resolver(fixture.credential.reference))
        except Exception as exc:
            raise MissionPrerequisiteError("race execution requires an HTTP fixture credential") from exc
        attempts = int(payload.get("attempts") or 2)
        method = str(payload.get("method") or "POST").upper()
        if method not in {"POST", "PUT", "PATCH", "DELETE"}:
            raise MissionPrerequisiteError("race candidate must be an explicitly selected mutation")
        if attempts + 2 > authorization.budget.max_requests:
            raise MissionPrerequisiteError("race request and state-readback budget is insufficient")
        resource_doc = payload.get("resource")
        if not isinstance(resource_doc, Mapping):
            raise MissionPrerequisiteError("race execution requires a synthetic resource")
        resource = SyntheticResource(
            str(resource_doc.get("resource_id") or ""),
            fixture.principal_id,
            fixture.tenant,
            str(resource_doc.get("canary") or ""),
            bool(resource_doc.get("synthetic", True)),
        )
        if not resource.synthetic or not resource.resource_id or not resource.canary:
            raise MissionPrerequisiteError("race resource must be synthetic and canary-marked")
        state_path = str(payload.get("state_path") or "")
        operation_path = str(payload.get("operation_path") or "")
        if not state_path or not operation_path:
            raise MissionPrerequisiteError("race execution requires operation and state-readback paths")
        state_url = urljoin(binding.endpoint.rstrip("/") + "/", state_path.lstrip("/"))
        operation_url = urljoin(binding.endpoint.rstrip("/") + "/", operation_path.lstrip("/"))
        before = self.http.request("GET", state_url, authorization=authorization, headers=headers)
        before_digest = sha256(before.body).hexdigest()
        key = str(payload.get("idempotency_key") or task.idempotency_key or "")
        body = str(payload.get("body_template") or "").replace(
            "{resource_id}", resource.resource_id
        ).replace("{canary}", resource.canary).encode()

        def operation(index: int) -> AttemptResult:
            request_headers = dict(headers)
            request_headers["x-request-id"] = f"{task.task_id}:{index}"
            if key:
                request_headers["idempotency-key"] = key
            try:
                response = self.http.request(
                    method, operation_url, authorization=authorization,
                    headers=request_headers, body=body,
                )
                effect_ids = self._effect_ids(response.body, str(payload.get("effect_id_field") or "effect_id"))
                digest = sha256(response.body).hexdigest()
                return AttemptResult(
                    f"{task.task_id}:{index}", response.status_code, effect_ids, digest,
                    evidence=(f"response-sha256:{digest}",),
                )
            except Exception as exc:
                return AttemptResult(
                    f"{task.task_id}:{index}", None, timed_out=True,
                    evidence=(f"executor-error:{type(exc).__name__}",),
                )

        results = self.harness.run(
            attempts=attempts, operation=operation, authorization=authorization
        )
        after = self.http.request("GET", state_url, authorization=authorization, headers=headers)
        after_digest = sha256(after.body).hexdigest()
        experiment = RaceExperiment(
            task.idempotency_key or task.task_id,
            results,
            before_digest,
            after_digest,
            int(payload.get("max_allowed_effects") or 1),
            sha256(key.encode()).hexdigest() if key else "",
            True,
            True,
        )
        verdict = self.agent.evaluate(experiment)
        verifications = tuple(
            self.state_verifier.verify(AccessObservation(
                fixture.principal(), resource, task.action, result.status_code,
                before_state_digest=before_digest, after_state_digest=after_digest,
                side_effects=result.effect_ids, timed_out=result.timed_out,
                correlation_id=result.attempt_id, evidence=result.evidence,
            ), expected_effects=tuple(str(item) for item in payload.get("expected_effects", ())))
            for result in results if result.timed_out or result.status_code is None
            or result.status_code >= 500
        )
        evidence = EvidenceBundle(
            steps=[InteractionStep(
                summary="synchronized bounded mutation attempt",
                request=f"attempt={row.attempt_id}; method={method}",
                response=f"status={row.status_code}; effects={len(row.effect_ids)}",
            ) for row in results],
            canary=Canary(kind=CanaryKind.SEEDED_RECORD, value=resource.canary),
            observed=verdict.reason,
            expected="bounded attempts must preserve the declared effect invariant",
            replay_ref=verdict.verdict_id,
            confidence=verdict.confidence,
            artifacts=list(verdict.evidence),
        )
        return RaceExecutionOutcome(experiment, verdict, verifications, evidence)

    @staticmethod
    def _effect_ids(body: bytes, field: str) -> tuple[str, ...]:
        try:
            document = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return ()
        value = document.get(field) if isinstance(document, dict) else None
        if isinstance(value, list):
            return tuple(str(item) for item in value if item is not None)
        return (str(value),) if value is not None else ()

    def _authorize(self, task, plan, authorization) -> None:
        grant = authorization.grant
        if (task.executor_capability not in self.CAPABILITIES or grant is None
                or grant.scope_digest != plan.scope_digest
                or authorization.scope_digest != plan.scope_digest
                or not grant.verify(self.grant_verifier) or not grant.network_allowed
                or not grant.state_change_allowed or not grant.human_approval):
            raise PermissionError("race execution requires a verified state-change grant")

    def runtime_executors(self) -> dict[str, object]:
        return {capability: self for capability in self.CAPABILITIES}


__all__ = ["RaceExecutionOutcome", "ScopedRaceIdempotencyExecutor"]
