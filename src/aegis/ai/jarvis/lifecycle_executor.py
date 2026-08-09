"""Bounded pre/action/post state verification over canonical scoped HTTP."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
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
from .scoped_http_executor import ScopedEgressHttpExecutor

CredentialResolver = Callable[[str], Mapping[str, str]]


@dataclass(frozen=True, slots=True)
class LifecycleTransitionExecution:
    from_state: str
    expected_to_state: str
    observed_to_state: str
    allowed: bool
    violation: bool
    policy_evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LifecycleExecutionOutcome:
    observation: AccessObservation
    verification: StateVerification
    transition: LifecycleTransitionExecution | None
    evidence: EvidenceBundle


class ScopedLifecycleStateExecutor:
    CAPABILITIES = frozenset({
        "dynamic:lifecycle-state-differential",
        "dynamic:post-error-state-verifier",
        "dynamic:partial-commit-verifier",
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
        self.verifier = ErrorStateVerifier()

    def __call__(self, task: MissionTask, plan: MissionPlan, authorization: AuthorizationEnvelope):
        self._authorize(task, plan, authorization)
        payload = task.payload or {}
        fixtures = self.fixture_sets.get(str(payload.get("fixture_set_id") or ""))
        if fixtures is None:
            raise MissionPrerequisiteError("controlled lifecycle fixture set is not registered")
        if fixtures.scope_digest != plan.scope_digest:
            raise PermissionError("lifecycle fixture set is bound to a different mission scope")
        try:
            binding = fixtures.require_protocol(FixtureProtocol.HTTP)
            fixture = fixtures.fixtures[FixtureKind(str(payload.get("fixture_kind") or "owner"))]
            resource_doc = dict(payload["resource"])
            resource = SyntheticResource(
                str(resource_doc["resource_id"]), str(resource_doc["owner_id"]),
                str(resource_doc["tenant"]), str(resource_doc["canary"]),
                bool(resource_doc.get("synthetic", True)),
            )
            pre_spec = dict(payload["pre_state"])
            action_spec = dict(payload["action"])
            post_spec = dict(payload["post_state"])
            expected_effects = tuple(str(item) for item in payload.get("expected_effects") or ())
            effect_assertions = tuple(dict(item) for item in payload.get("effect_assertions") or ())
        except (KeyError, TypeError, ValueError, LookupError) as exc:
            raise MissionPrerequisiteError(
                "lifecycle execution requires controlled resource and pre/action/post specifications"
            ) from exc
        if not resource.synthetic or not resource.canary:
            raise MissionPrerequisiteError("lifecycle execution requires a synthetic canary resource")
        if task.executor_capability == "dynamic:partial-commit-verifier" and not expected_effects:
            raise MissionPrerequisiteError("partial-commit verification requires expected effects")
        headers = self._credentials(fixture.credential.reference)
        before = self._send(binding.endpoint, pre_spec, resource, headers, authorization)
        action = self._send(binding.endpoint, action_spec, resource, headers, authorization)
        after = self._send(binding.endpoint, post_spec, resource, headers, authorization)
        before_digest = sha256(before.body).hexdigest()
        after_digest = sha256(after.body).hexdigest()
        observed_effects = self._effects(after.body, effect_assertions)
        observation = AccessObservation(
            principal=fixture.principal(), resource=resource,
            operation=str(payload.get("operation") or task.action),
            status_code=action.status_code,
            response_digest=sha256(action.body).hexdigest(),
            returned_markers=(resource.canary,) if resource.canary.encode() in after.body else (),
            before_state_digest=before_digest,
            after_state_digest=after_digest,
            side_effects=observed_effects,
            correlation_id=f"lifecycle:{sha256((task.task_id + before_digest + after_digest).encode()).hexdigest()[:20]}",
            evidence=tuple(dict.fromkeys((
                f"binding:{binding.endpoint}", *binding.evidence,
                f"before-sha256:{before_digest}", f"action-status:{action.status_code}",
                f"after-sha256:{after_digest}",
            ))),
        )
        verification = self.verifier.verify(observation, expected_effects=expected_effects)
        transition = self._transition(payload, before.body, after.body)
        evidence = self._evidence(resource, observation, verification, transition)
        return LifecycleExecutionOutcome(observation, verification, transition, evidence)

    def _authorize(self, task, plan, authorization):
        grant = authorization.grant
        if (
            task.executor_capability not in self.CAPABILITIES
            or grant is None
            or authorization.scope_digest != plan.scope_digest
            or grant.scope_digest != plan.scope_digest
            or not grant.verify(self.grant_verifier)
            or not grant.network_allowed
            or not grant.state_change_allowed
            or not grant.human_approval
        ):
            raise PermissionError("lifecycle execution requires an exact verified grant")

    def _credentials(self, reference):
        try:
            headers = dict(self.credential_resolver(reference))
        except Exception as exc:
            raise MissionPrerequisiteError(
                f"operator credential reference could not be resolved: {reference}"
            ) from exc
        if not headers:
            raise MissionPrerequisiteError("lifecycle credential resolved to no headers")
        return headers

    def _send(self, endpoint, spec, resource, headers, authorization):
        path = str(spec.get("path") or "")
        if not path.startswith("/") or path.startswith("//"):
            raise MissionPrerequisiteError("lifecycle request paths must be absolute local paths")
        method = str(spec.get("method") or "GET").upper()
        body = self._render(str(spec.get("body_template") or ""), resource).encode()
        return self.http.request(
            method, urljoin(endpoint, path), authorization=authorization,
            headers=headers, body=body,
        )

    @staticmethod
    def _render(value, resource):
        return value.replace("{resource_id}", resource.resource_id).replace(
            "{canary}", resource.canary,
        )

    @classmethod
    def _effects(cls, body, assertions):
        try:
            document = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return ()
        observed = []
        for assertion in assertions:
            name = str(assertion.get("name") or "")
            path = str(assertion.get("json_path") or "")
            if name and path and cls._json_path(document, path) == assertion.get("equals"):
                observed.append(name)
        return tuple(observed)

    @classmethod
    def _transition(cls, payload, before_body, after_body):
        if not payload.get("state_json_path"):
            return None
        try:
            before = json.loads(before_body)
            after = json.loads(after_body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise MissionPrerequisiteError("lifecycle state readback must be JSON") from exc
        path = str(payload["state_json_path"])
        from_state = str(cls._json_path(before, path))
        observed_to = str(cls._json_path(after, path))
        expected_to = str(payload.get("to_state") or "")
        expected_from = str(payload.get("from_state") or "")
        evidence = tuple(str(item) for item in payload.get("transition_policy_evidence") or ())
        if not expected_from or not expected_to or not evidence:
            raise MissionPrerequisiteError("lifecycle transition requires states and policy evidence")
        if from_state != expected_from:
            raise MissionPrerequisiteError("pre-state did not match the registered transition")
        allowed = bool(payload.get("transition_allowed"))
        return LifecycleTransitionExecution(
            from_state, expected_to, observed_to, allowed,
            (not allowed and observed_to == expected_to), evidence,
        )

    @staticmethod
    def _json_path(document, path):
        value = document
        for part in path.split("."):
            if not isinstance(value, Mapping) or part not in value:
                return None
            value = value[part]
        return value

    @staticmethod
    def _evidence(resource, observation, verification, transition):
        artifacts = list(verification.evidence)
        if transition is not None:
            artifacts.extend(transition.policy_evidence)
        return EvidenceBundle(
            steps=[
                InteractionStep(
                    summary="synthetic pre-state snapshot",
                    response=f"sha256={observation.before_state_digest}",
                ),
                InteractionStep(
                    summary="bounded lifecycle action",
                    response=f"status={observation.status_code}; sha256={observation.response_digest}",
                ),
                InteractionStep(
                    summary="post-action state verification",
                    response=f"sha256={observation.after_state_digest}; effects={len(observation.side_effects)}",
                ),
            ],
            canary=Canary(
                kind=CanaryKind.SEEDED_RECORD, value=resource.canary,
                note="operator-controlled lifecycle resource",
            ),
            observed=(
                "forbidden lifecycle transition completed" if transition and transition.violation
                else verification.reason
            ),
            expected="state and atomic effects must match the registered lifecycle policy",
            replay_ref=verification.verification_id,
            confidence=max(verification.confidence, 0.95 if transition and transition.violation else 0.0),
            artifacts=list(dict.fromkeys(artifacts)),
        )

    def runtime_executors(self) -> dict[str, object]:
        return {capability: self for capability in self.CAPABILITIES}


__all__ = [
    "LifecycleExecutionOutcome", "LifecycleTransitionExecution", "ScopedLifecycleStateExecutor",
]
