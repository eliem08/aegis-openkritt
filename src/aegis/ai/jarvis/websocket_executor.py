"""Grant-bound WebSocket identity and state differential execution."""

from __future__ import annotations

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

POLICY_ACTION = "hunter.websocket.execute"
WebSocketTokenIssuer = Callable[[str, str, AuthorizationEnvelope], str]
CredentialResolver = Callable[[str], Mapping[str, str]]


@dataclass(frozen=True, slots=True)
class ScopedWebSocketResponse:
    handshake_status: int
    selected_protocol: str | None
    messages: tuple[str, ...]
    close_code: int | None


class ScopedWebSocketTransport:
    """Use the scoped egress sidecar for a bounded RFC6455 session."""

    def __init__(
        self,
        endpoint: str,
        *,
        token_issuer: WebSocketTokenIssuer,
        grant_verifier,
        max_sessions: int = 8,
        max_actions: int = 32,
        max_actions_per_second: int = 16,
        timeout_seconds: float = 8.0,
        client=None,
    ) -> None:
        parts = urlsplit(endpoint)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("scoped WebSocket egress endpoint must be HTTP(S)")
        self.endpoint = endpoint.rstrip("/") + "/v1/websocket"
        self.token_issuer = token_issuer
        self.grant_verifier = grant_verifier
        self.max_sessions = max_sessions
        self.max_actions = max_actions
        if max_actions_per_second <= 0:
            raise ValueError("WebSocket action rate budget must be positive")
        self.max_actions_per_second = max_actions_per_second
        self.timeout_seconds = timeout_seconds
        self.client = client
        self.sessions = 0
        self.actions = 0
        self._budget_lock = Lock()
        self._window_started = time.monotonic()
        self._window_actions = 0

    def session(
        self,
        url: str,
        *,
        authorization: AuthorizationEnvelope,
        headers: Mapping[str, str],
        messages: tuple[str, ...],
        receive_limit: int = 8,
    ) -> ScopedWebSocketResponse:
        grant = authorization.grant
        if (
            grant is None
            or grant.scope_digest != authorization.scope_digest
            or not grant.verify(self.grant_verifier)
            or not grant.network_allowed
            or not grant.state_change_allowed
        ):
            raise PermissionError("WebSocket execution requires a verified state-change grant")
        if urlsplit(url).scheme not in {"ws", "wss"}:
            raise MissionPrerequisiteError("controlled WebSocket binding must use ws:// or wss://")
        actions = len(messages) + 1
        authorized_limit = min(
            self.max_actions,
            max(0, authorization.budget.max_requests),
            max(0, grant.budget.max_requests),
        )
        with self._budget_lock:
            now = time.monotonic()
            if now - self._window_started >= 1.0:
                self._window_started = now
                self._window_actions = 0
            if self.sessions >= self.max_sessions or self.actions + actions > authorized_limit:
                raise RuntimeError("WebSocket execution budget exhausted")
            if self._window_actions + actions > self.max_actions_per_second:
                raise RuntimeError("WebSocket execution rate budget exhausted")
            self.sessions += 1
            self.actions += actions
            self._window_actions += actions
        token = self.token_issuer(POLICY_ACTION, url, authorization)
        if not token:
            raise PermissionError("egress token issuer refused the WebSocket destination")
        payload = {
            "url": url,
            "headers": dict(headers),
            "messages": list(messages),
            "receive_limit": receive_limit,
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
            return ScopedWebSocketResponse(
                handshake_status=int(document["handshake_status"]),
                selected_protocol=(str(document["selected_protocol"])
                                   if document.get("selected_protocol") else None),
                messages=tuple(str(item) for item in document.get("messages") or ()),
                close_code=(int(document["close_code"])
                            if document.get("close_code") is not None else None),
            )
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
            raise MissionBackendUnavailableError(
                f"scoped WebSocket egress failed to produce a valid response: {exc}"
            ) from exc


@dataclass(frozen=True, slots=True)
class WebSocketIdentityExecutionOutcome:
    observations: tuple[AccessObservation, ...]
    verdicts: tuple[DifferentialVerdict, ...]
    sessions: tuple[ScopedWebSocketResponse, ...]
    evidence: tuple[EvidenceBundle, ...]


class WebSocketIdentityDifferentialExecutor:
    """Compare subscriptions and messages for operator-controlled identities."""

    CAPABILITY = "dynamic:websocket-state-differential"

    def __init__(
        self,
        transport: ScopedWebSocketTransport,
        *,
        fixture_sets: Mapping[str, ControlledIdentityFixtureSet],
        credential_resolver: CredentialResolver,
        grant_verifier,
    ) -> None:
        self.transport = transport
        self.fixture_sets = dict(fixture_sets)
        self.credential_resolver = credential_resolver
        self.grant_verifier = grant_verifier
        self.oracle = IdentityDifferentialOracle()

    def __call__(
        self, task: MissionTask, plan: MissionPlan, authorization: AuthorizationEnvelope,
    ) -> WebSocketIdentityExecutionOutcome:
        self._authorize(task, plan, authorization)
        payload = task.payload or {}
        fixtures = self.fixture_sets.get(str(payload.get("fixture_set_id") or ""))
        if fixtures is None:
            raise MissionPrerequisiteError("controlled WebSocket identity fixtures are not registered")
        if fixtures.scope_digest != plan.scope_digest:
            raise PermissionError("controlled fixture set is bound to a different mission scope")
        try:
            binding = fixtures.require_protocol(FixtureProtocol.WEBSOCKET)
            resource_doc = dict(payload["resource"])
            resource = SyntheticResource(
                resource_id=str(resource_doc["resource_id"]),
                owner_id=str(resource_doc["owner_id"]),
                tenant=str(resource_doc["tenant"]),
                canary=str(resource_doc["canary"]),
                synthetic=bool(resource_doc.get("synthetic", True)),
            )
            operation = str(payload["operation"])
            templates = tuple(str(payload[name]) for name in (
                "subscription_template", "message_template", "state_recheck_template",
            ))
            denial_markers = tuple(str(item) for item in payload["denial_markers"])
        except (KeyError, TypeError, ValueError, LookupError) as exc:
            raise MissionPrerequisiteError(
                "WebSocket differential requires binding, resource, three messages, and denial markers"
            ) from exc
        if not resource.synthetic or not resource.canary or not all(templates) or not denial_markers:
            raise MissionPrerequisiteError(
                "WebSocket differential requires a synthetic canary and explicit controls"
            )
        owner = fixtures.fixtures.get(FixtureKind.OWNER)
        probes = [
            fixture for kind, fixture in sorted(
                fixtures.fixtures.items(), key=lambda item: item[0].value,
            ) if kind is not FixtureKind.OWNER
        ]
        if owner is None or not probes:
            raise MissionPrerequisiteError("WebSocket differential requires owner and probe identities")
        matrix = fixtures.authorization_matrix(resource)
        observations = []
        sessions = []
        for fixture in (owner, *probes):
            messages = tuple(
                self._render(template, resource, fixture.principal_id) for template in templates
            )
            try:
                headers = dict(self.credential_resolver(fixture.credential.reference))
            except Exception as exc:
                raise MissionPrerequisiteError(
                    f"operator credential reference could not be resolved: {fixture.credential.reference}"
                ) from exc
            if not headers:
                raise MissionPrerequisiteError("WebSocket credential resolved to no handshake headers")
            session = self.transport.session(
                binding.endpoint,
                authorization=authorization,
                headers=headers,
                messages=messages,
                receive_limit=int(payload.get("receive_limit") or 8),
            )
            sessions.append(session)
            observations.append(self._observation(
                fixture.principal(), resource, operation, session, denial_markers,
                evidence=(f"binding:{binding.endpoint}", *binding.evidence),
            ))
        control = observations[0]
        verdicts = tuple(self.oracle.evaluate(control, probe, matrix) for probe in observations[1:])
        evidence = tuple(
            self._evidence(control, probe, verdict, resource, sessions[0], sessions[index + 1])
            for index, (probe, verdict) in enumerate(zip(observations[1:], verdicts, strict=True))
        )
        return WebSocketIdentityExecutionOutcome(
            tuple(observations), verdicts, tuple(sessions), evidence,
        )

    def _authorize(
        self, task: MissionTask, plan: MissionPlan, authorization: AuthorizationEnvelope,
    ) -> None:
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
            raise PermissionError("WebSocket differential requires an exact verified grant")

    @staticmethod
    def _render(template: str, resource: SyntheticResource, principal_id: str) -> str:
        return (template.replace("{resource_id}", resource.resource_id)
                .replace("{canary}", resource.canary)
                .replace("{principal_id}", principal_id))

    @staticmethod
    def _observation(principal, resource, operation, session, denial_markers, *, evidence):
        transcript = "\n".join(session.messages)
        digest = sha256(transcript.encode("utf-8")).hexdigest()
        returned = (resource.canary,) if resource.canary in transcript else ()
        denied = any(marker in transcript for marker in denial_markers)
        status = 200 if returned else (403 if denied else session.handshake_status)
        return AccessObservation(
            principal=principal,
            resource=resource,
            operation=operation,
            status_code=status,
            response_digest=digest,
            returned_markers=returned,
            correlation_id=f"websocket:{digest[:20]}",
            evidence=tuple(dict.fromkeys((
                *evidence, f"handshake-status:{session.handshake_status}",
                f"transcript-sha256:{digest}", f"close-code:{session.close_code}",
            ))),
        )

    @staticmethod
    def _evidence(control, probe, verdict, resource, control_session, probe_session):
        return EvidenceBundle(
            steps=[
                InteractionStep(
                    summary="controlled WebSocket handshake and subscription",
                    request=f"principal={control.principal.principal_id}; messages=3",
                    response=(f"handshake={control_session.handshake_status}; "
                              f"sha256={control.response_digest}"),
                ),
                InteractionStep(
                    summary="controlled cross-identity message authorization probe",
                    request=f"principal={probe.principal.principal_id}; messages=3",
                    response=(f"handshake={probe_session.handshake_status}; "
                              f"sha256={probe.response_digest}"),
                ),
                InteractionStep(
                    summary="state re-check on established sessions",
                    response=f"control-close={control_session.close_code}; probe-close={probe_session.close_code}",
                ),
            ],
            canary=Canary(
                kind=CanaryKind.SEEDED_RECORD,
                value=resource.canary,
                note="operator-controlled WebSocket channel marker",
            ),
            observed=verdict.reason,
            expected="subscription and message access must match the authorization matrix",
            replay_ref=verdict.verdict_id,
            confidence=verdict.confidence,
            artifacts=list(verdict.evidence),
        )

    def runtime_executors(self) -> dict[str, object]:
        return {self.CAPABILITY: self}


__all__ = [
    "POLICY_ACTION", "ScopedWebSocketResponse", "ScopedWebSocketTransport",
    "WebSocketIdentityDifferentialExecutor", "WebSocketIdentityExecutionOutcome",
]
