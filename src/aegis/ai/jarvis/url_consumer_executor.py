"""Real scoped URL-consumer validation with private OAST correlation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urljoin

from aegis.ai.agentic_os import AuthorizationEnvelope
from aegis.model.evidence import Canary, CanaryKind, EvidenceBundle, InteractionStep

from .execution_errors import MissionObservationPending, MissionPrerequisiteError
from .identity_fixtures import ControlledIdentityFixtureSet, FixtureKind, FixtureProtocol
from .mission_scheduler import MissionPlan, MissionTask
from .scoped_http_executor import ScopedEgressHttpExecutor
from .url_consumer_intelligence import (
    CallbackObservation,
    ConsumerDelivery,
    ServerSideURLConsumerAgent,
    URLConsumerProbe,
    URLConsumerVerdict,
    surface_from_route,
)


@dataclass(frozen=True, slots=True)
class URLConsumerExecutionOutcome:
    verdict: URLConsumerVerdict
    evidence: EvidenceBundle


class ScopedURLConsumerExecutor:
    CAPABILITIES = frozenset({
        "dynamic:server-url-consumer",
        "dynamic:async-url-consumer",
        "dynamic:url-consumer-behavior-classifier",
    })

    def __init__(self, http: ScopedEgressHttpExecutor, *, fixture_sets,
                 credential_resolver, grant_verifier, oast_service, oast_principal) -> None:
        self.http = http
        self.fixture_sets: Mapping[str, ControlledIdentityFixtureSet] = dict(fixture_sets)
        self.credential_resolver = credential_resolver
        self.grant_verifier = grant_verifier
        self.oast_service = oast_service
        self.oast_principal = oast_principal
        self.agent = ServerSideURLConsumerAgent()

    def __call__(self, task: MissionTask, plan: MissionPlan,
                 authorization: AuthorizationEnvelope) -> URLConsumerExecutionOutcome:
        self._authorize(task, plan, authorization)
        payload = task.payload or {}
        fixtures = self.fixture_sets.get(str(payload.get("fixture_set_id") or ""))
        if fixtures is None:
            raise MissionPrerequisiteError("URL-consumer fixture set is not registered")
        if fixtures.scope_digest != plan.scope_digest:
            raise PermissionError("URL-consumer fixtures are bound to another scope")
        try:
            binding = fixtures.require_protocol(FixtureProtocol.HTTP)
            owner = fixtures.fixtures[FixtureKind.OWNER]
            headers = dict(self.credential_resolver(owner.credential.reference))
            session_ref = str(payload["oast_session_ref"])
            route = str(payload["route"])
            parameter = str(payload["parameter"])
        except Exception as exc:
            raise MissionPrerequisiteError(
                "URL-consumer execution requires owner credentials, route, parameter, and OAST session"
            ) from exc
        probe_token = self.oast_service.plant_probe(session_ref, self.oast_principal)
        requested_at = datetime.now(UTC)
        probe_url = "https://" + probe_token.address
        body_template = str(payload.get("body_template") or '{"url":"{probe_url}"}')
        body = body_template.replace("{probe_url}", probe_url).encode()
        method = str(payload.get("method") or "POST").upper()
        if method not in {"POST", "PUT", "PATCH"}:
            raise MissionPrerequisiteError("URL-consumer validation requires a bounded write method")
        response = self.http.request(
            method,
            urljoin(binding.endpoint.rstrip("/") + "/", route.lstrip("/")),
            authorization=authorization,
            headers={"content-type": "application/json", **headers},
            body=body,
        )
        matched = tuple(self.oast_service.poll(session_ref, self.oast_principal))
        callbacks = tuple(CallbackObservation(
            item.host, item.protocol, item.remote_address, item.observed_at,
            item.interaction_id,
        ) for item in matched if item.host == probe_token.address)
        try:
            delivery = ConsumerDelivery(str(payload.get("delivery") or "unknown"))
        except ValueError as exc:
            raise MissionPrerequisiteError("URL-consumer delivery mode is invalid") from exc
        surface = surface_from_route(
            route=route,
            parameter=parameter,
            authorized=True,
            evidence=(f"mission:{plan.mission_id}", f"task:{task.task_id}", *binding.evidence),
            delivery=delivery,
        )
        probe = URLConsumerProbe(
            probe_id=f"{plan.mission_id}:{task.task_id}:{probe_token.probe_id}",
            surface=surface,
            probe_address=probe_token.address,
            private_oast_domain=probe_token.address.split(".", 1)[1],
            requested_at=requested_at,
            callbacks=callbacks,
            job_correlation=str(payload.get("job_correlation") or ""),
            polling_complete=bool(callbacks),
            evidence=(
                f"mission:{plan.mission_id}", f"task:{task.task_id}",
                f"requested-at:{requested_at.isoformat()}",
                f"expected-host:{probe_token.address}",
                f"submission-status:{response.status_code}",
            ),
        )
        verdict = self.agent.analyze(probe)
        if not callbacks:
            raise MissionObservationPending(
                f"private OAST observation pending for {probe_token.address}"
            )
        evidence = EvidenceBundle(
            steps=[
                InteractionStep(
                    summary="submitted private OAST URL to authorized consumer",
                    request=f"route={route}; parameter={parameter}",
                    response=f"status={response.status_code}",
                ),
                InteractionStep(
                    summary="matched exact private OAST callback",
                    response=f"host={probe_token.address}; interactions={len(callbacks)}",
                ),
            ],
            canary=Canary(
                kind=CanaryKind.CONTROLLED_EVAL,
                value=probe_token.address,
                note="private, session-bound OAST probe hostname",
            ),
            observed=verdict.reason,
            expected="only an exact outstanding private OAST callback confirms server-side fetching",
            replay_ref=verdict.verdict_id,
            confidence=verdict.confidence,
            artifacts=list(verdict.evidence),
        )
        return URLConsumerExecutionOutcome(verdict, evidence)

    def _authorize(self, task, plan, authorization) -> None:
        grant = authorization.grant
        if (task.executor_capability not in self.CAPABILITIES or grant is None
                or authorization.scope_digest != plan.scope_digest
                or grant.scope_digest != plan.scope_digest
                or not grant.verify(self.grant_verifier) or not grant.network_allowed
                or not grant.state_change_allowed or not grant.human_approval):
            raise PermissionError("URL-consumer execution requires a verified state-change grant")

    def runtime_executors(self) -> dict[str, object]:
        return {capability: self for capability in self.CAPABILITIES}


__all__ = ["ScopedURLConsumerExecutor", "URLConsumerExecutionOutcome"]
