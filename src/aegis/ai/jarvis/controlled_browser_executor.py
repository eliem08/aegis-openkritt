"""Canonical controlled-browser execution for OAuth and authentication workflows."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol

from aegis.ai.agentic_os import AuthorizationEnvelope
from aegis.browser import BrowserWorkflow
from aegis.model.evidence import Canary, CanaryKind, EvidenceBundle, InteractionStep

from .execution_errors import MissionBackendUnavailableError, MissionPrerequisiteError
from .mission_scheduler import MissionPlan, MissionTask
from .oauth_intelligence import (
    AuthWorkflowVerdict,
    OAuthClientPolicy,
    OAuthFlowObservation,
    OAuthTrustGraphAgent,
    RecoveryObservation,
    SessionInvalidationObservation,
)


@dataclass(frozen=True, slots=True)
class RegisteredBrowserExperiment:
    experiment_id: str
    capability: str
    scope_digest: str
    base_url: str
    workflow: BrowserWorkflow
    synthetic_account: bool
    evidence: tuple[str, ...]
    oauth_policy: OAuthClientPolicy | None = None
    field_extractors: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not all((self.experiment_id, self.capability, self.scope_digest, self.base_url)):
            raise ValueError("browser experiment registration is incomplete")
        if not self.synthetic_account or not self.evidence:
            raise ValueError("browser experiments require a synthetic account and scope evidence")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", self.experiment_id) is None:
            raise ValueError("browser experiment id is not artifact-safe")
        self.workflow.validate()


@dataclass(frozen=True, slots=True)
class ControlledBrowserCapture:
    status: int
    final_url: str
    html_sha256: str
    screenshot_sha256: str
    artifact_refs: tuple[str, ...]
    fields: Mapping[str, object]
    evidence: tuple[str, ...]


class ControlledBrowserBackend(Protocol):
    def execute(
        self,
        experiment: RegisteredBrowserExperiment,
        *,
        inputs: Mapping[str, str],
    ) -> ControlledBrowserCapture: ...


@dataclass(frozen=True, slots=True)
class ControlledBrowserExecutionOutcome:
    capture: ControlledBrowserCapture
    verdicts: tuple[AuthWorkflowVerdict, ...]
    evidence: tuple[EvidenceBundle, ...]


class ControlledBrowserWorkflowExecutor:
    CAPABILITIES = frozenset({
        "dynamic:oauth-trust-differential",
        "dynamic:postmessage-trust-differential",
        "dynamic:recovery-state-differential",
        "dynamic:session-invalidation-differential",
    })

    def __init__(
        self,
        backend: ControlledBrowserBackend,
        *,
        experiments: Mapping[str, RegisteredBrowserExperiment],
        grant_verifier,
    ) -> None:
        self.backend = backend
        self.experiments = dict(experiments)
        self.grant_verifier = grant_verifier
        self.oracle = OAuthTrustGraphAgent()

    def __call__(self, task: MissionTask, plan: MissionPlan, authorization: AuthorizationEnvelope):
        self._authorize(task, plan, authorization)
        payload = task.payload or {}
        experiment = self.experiments.get(str(payload.get("experiment_id") or ""))
        if experiment is None:
            raise MissionPrerequisiteError("operator-registered browser experiment is required")
        if experiment.scope_digest != plan.scope_digest:
            raise PermissionError("browser experiment is bound to a different mission scope")
        if experiment.capability != task.executor_capability:
            raise PermissionError("browser experiment is registered for a different capability")
        raw_inputs = payload.get("inputs") or {}
        if not isinstance(raw_inputs, Mapping):
            raise MissionPrerequisiteError("browser experiment inputs must be a mapping")
        inputs = {str(key): str(value) for key, value in raw_inputs.items()}
        if any(key.casefold() in {"password", "secret", "token", "cookie"} for key in inputs):
            raise MissionPrerequisiteError("browser secrets must remain registered credential references")
        try:
            capture = self.backend.execute(experiment, inputs=inputs)
        except (MissionPrerequisiteError, PermissionError):
            raise
        except Exception as exc:
            raise MissionBackendUnavailableError(f"controlled browser backend failed: {exc}") from exc
        verdicts = self._verdicts(task.executor_capability, experiment, capture, inputs)
        bundles = tuple(self._evidence(experiment, capture, verdict) for verdict in verdicts)
        return ControlledBrowserExecutionOutcome(capture, verdicts, bundles)

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
            raise PermissionError("browser workflow requires an exact verified state-change grant")

    def _verdicts(self, capability, experiment, capture, inputs):
        evidence = tuple(dict.fromkeys((*experiment.evidence, *capture.evidence,
                                        *capture.artifact_refs)))
        fields = capture.fields
        if capability in {
            "dynamic:oauth-trust-differential", "dynamic:postmessage-trust-differential",
        }:
            if experiment.oauth_policy is None:
                raise MissionPrerequisiteError("OAuth browser experiment requires client policy")
            state_sent = inputs.get("state", "")
            nonce_sent = inputs.get("nonce", "")
            state_returned = str(fields.get("state_returned") or "")
            nonce_returned = str(fields.get("nonce_returned") or "")
            observation = OAuthFlowObservation(
                flow_id=experiment.experiment_id,
                policy=experiment.oauth_policy,
                supplied_redirect_uri=inputs.get("redirect_uri", ""),
                authorization_accepted=bool(fields.get("authorization_accepted")),
                state_sent_digest=self._digest(state_sent),
                state_returned_digest=self._digest(state_returned),
                nonce_sent_digest=self._digest(nonce_sent),
                nonce_returned_digest=self._digest(nonce_returned),
                pkce_challenge_digest=self._digest(inputs.get("pkce_challenge", "")),
                pkce_method=inputs.get("pkce_method", ""),
                postmessage_sender_origin=str(fields.get("postmessage_sender_origin") or ""),
                postmessage_target_origin=str(fields.get("postmessage_target_origin") or ""),
                postmessage_sensitive_payload=bool(fields.get("postmessage_sensitive_payload")),
                synthetic_account=True,
                authorized=True,
                evidence=evidence,
            )
            rows = self.oracle.analyze_flow(observation)
            if capability == "dynamic:postmessage-trust-differential":
                rows = tuple(row for row in rows if row.check == "postmessage_origin")
                if not rows:
                    raise MissionPrerequisiteError("browser flow produced no postMessage observation")
            return rows
        if capability == "dynamic:recovery-state-differential":
            token_digest = str(fields.get("recovery_token_digest") or "")
            observation = RecoveryObservation(
                experiment.experiment_id, token_digest,
                bool(fields.get("first_use_succeeded")), bool(fields.get("reuse_succeeded")),
                bool(fields.get("old_session_usable_after_reset")), True, True, evidence,
            )
            return self.oracle.analyze_recovery(observation)
        session_digest = str(fields.get("session_digest") or "")
        observation = SessionInvalidationObservation(
            experiment.experiment_id, session_digest, str(fields.get("event") or ""),
            bool(fields.get("usable_before")), bool(fields.get("usable_after")),
            True, True, evidence,
        )
        return (self.oracle.analyze_session(observation),)

    @staticmethod
    def _digest(value: str) -> str:
        return sha256(value.encode("utf-8")).hexdigest() if value else ""

    @staticmethod
    def _evidence(experiment, capture, verdict):
        marker = f"browser-capture:{capture.html_sha256[:20]}"
        return EvidenceBundle(
            steps=[InteractionStep(
                summary=f"controlled browser workflow: {verdict.check}",
                request=f"experiment={experiment.experiment_id}; identity={experiment.workflow.identity}",
                response=f"status={capture.status}; html-sha256={capture.html_sha256}",
            )],
            canary=Canary(
                kind=CanaryKind.CONTROLLED_EVAL,
                value=marker,
                note="redacted controlled-browser capture",
            ),
            observed=verdict.reason,
            expected="authentication workflow must match the registered trust policy",
            replay_ref=verdict.verdict_id,
            confidence=verdict.confidence,
            artifacts=list(dict.fromkeys((*capture.artifact_refs, *verdict.evidence))),
        )

    def runtime_executors(self) -> dict[str, object]:
        return {capability: self for capability in self.CAPABILITIES}


__all__ = [
    "ControlledBrowserBackend", "ControlledBrowserCapture", "ControlledBrowserExecutionOutcome",
    "ControlledBrowserWorkflowExecutor", "RegisteredBrowserExperiment",
]
