"""Bounded real cache differential execution over canonical scoped egress."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from urllib.parse import urljoin

from aegis.ai.agentic_os import AuthorizationEnvelope
from aegis.model.evidence import Canary, CanaryKind, EvidenceBundle, InteractionStep

from .cache_intelligence import (
    CacheArchitectureAgent,
    CacheExperiment,
    CacheObservation,
    CacheVerdict,
)
from .execution_errors import MissionPrerequisiteError
from .identity_fixtures import ControlledIdentityFixtureSet, FixtureKind, FixtureProtocol
from .mission_scheduler import MissionPlan, MissionTask
from .scoped_http_executor import ScopedEgressHttpExecutor


@dataclass(frozen=True, slots=True)
class CacheExecutionOutcome:
    experiment: CacheExperiment
    verdict: CacheVerdict
    evidence: EvidenceBundle


class CacheDifferentialExecutor:
    CAPABILITIES = frozenset({
        "dynamic:cache-key-differential",
        "dynamic:private-shared-cache-differential",
        "dynamic:web-cache-deception",
    })
    _CACHE_HEADERS = frozenset({
        "age", "via", "vary", "etag", "cache-control", "cache-status", "x-cache",
        "cf-cache-status", "x-served-by", "x-varnish", "content-type",
    })

    def __init__(self, http: ScopedEgressHttpExecutor, *, fixture_sets,
                 credential_resolver, grant_verifier) -> None:
        self.http = http
        self.fixture_sets: Mapping[str, ControlledIdentityFixtureSet] = dict(fixture_sets)
        self.credential_resolver = credential_resolver
        self.grant_verifier = grant_verifier
        self.agent = CacheArchitectureAgent()

    def __call__(self, task: MissionTask, plan: MissionPlan,
                 authorization: AuthorizationEnvelope) -> CacheExecutionOutcome:
        self._authorize(task, plan, authorization)
        payload = task.payload or {}
        fixtures = self.fixture_sets.get(str(payload.get("fixture_set_id") or ""))
        if fixtures is None:
            raise MissionPrerequisiteError("cache experiment fixture set is not registered")
        if fixtures.scope_digest != plan.scope_digest:
            raise PermissionError("cache fixtures are bound to a different mission scope")
        try:
            binding = fixtures.require_protocol(FixtureProtocol.HTTP)
        except LookupError as exc:
            raise MissionPrerequisiteError("cache experiment requires an HTTP binding") from exc
        marker = str(payload.get("marker") or "")
        if not marker:
            raise MissionPrerequisiteError("cache experiment requires a synthetic marker")
        rows = []
        for name in ("prime", "victim", "negative_control"):
            spec = payload.get(name)
            if not isinstance(spec, Mapping):
                raise MissionPrerequisiteError(f"cache experiment requires {name} request")
            rows.append(self._execute_request(
                name, spec, binding.endpoint, fixtures, marker, authorization
            ))
        experiment = CacheExperiment(
            experiment_id=task.idempotency_key or task.task_id,
            dimension=str(payload.get("dimension") or "unspecified"),
            marker=marker,
            prime=rows[0],
            victim=rows[1],
            negative_control=rows[2],
            authorized=True,
            private_marker=bool(payload.get("private_marker", False)),
        )
        verdict = self.agent.evaluate(experiment)
        evidence = EvidenceBundle(
            steps=[InteractionStep(
                summary=f"cache {row.request_id} controlled request",
                request=f"client={row.client_id}; path={row.path}",
                response=f"status={row.status_code}; sha256={row.body_digest}",
            ) for row in rows],
            canary=Canary(kind=CanaryKind.SYNTHETIC_MARKER, value=marker),
            observed=verdict.reason,
            expected="cache key boundaries must prevent cross-client synthetic marker propagation",
            replay_ref=verdict.verdict_id,
            confidence=verdict.confidence,
            artifacts=list(verdict.evidence),
        )
        return CacheExecutionOutcome(experiment, verdict, evidence)

    def _execute_request(self, request_id: str, spec: Mapping[str, object], base_url: str,
                         fixtures: ControlledIdentityFixtureSet, marker: str,
                         authorization: AuthorizationEnvelope) -> CacheObservation:
        method = str(spec.get("method") or "GET").upper()
        if method not in {"GET", "HEAD"}:
            raise MissionPrerequisiteError("cache matrices permit only GET or HEAD")
        raw_headers = spec.get("headers") or {}
        if not isinstance(raw_headers, Mapping) or len(raw_headers) > 8:
            raise MissionPrerequisiteError("cache request headers must be a mapping of at most 8 entries")
        kind_name = str(spec.get("fixture_kind") or "owner")
        try:
            kind = FixtureKind(kind_name)
            fixture = fixtures.fixtures[kind]
            credentials = dict(self.credential_resolver(fixture.credential.reference))
        except Exception as exc:
            raise MissionPrerequisiteError(
                f"cache request credential fixture is unavailable: {kind_name}"
            ) from exc
        path = str(spec.get("path") or "/")
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        response = self.http.request(
            method, url, authorization=authorization,
            headers={**{str(k): str(v) for k, v in raw_headers.items()}, **credentials},
        )
        digest = sha256(response.body).hexdigest()
        headers = {
            key.casefold(): value for key, value in response.headers.items()
            if key.casefold() in self._CACHE_HEADERS
        }
        return CacheObservation(
            request_id=request_id,
            client_id=fixture.principal_id,
            path=path,
            status_code=response.status_code,
            body_digest=digest,
            markers=(marker,) if marker.encode() in response.body else (),
            headers=headers,
            authenticated=bool(credentials),
            evidence=(f"response-sha256:{digest}", *fixture.credential.evidence),
        )

    def _authorize(self, task, plan, authorization) -> None:
        grant = authorization.grant
        if (task.executor_capability not in self.CAPABILITIES or grant is None
                or grant.scope_digest != plan.scope_digest
                or authorization.scope_digest != plan.scope_digest
                or not grant.verify(self.grant_verifier) or not grant.network_allowed
                or not grant.state_change_allowed or not grant.human_approval):
            raise PermissionError("cache differential requires a verified state-change grant")

    def runtime_executors(self) -> dict[str, object]:
        return {capability: self for capability in self.CAPABILITIES}


__all__ = ["CacheDifferentialExecutor", "CacheExecutionOutcome"]
