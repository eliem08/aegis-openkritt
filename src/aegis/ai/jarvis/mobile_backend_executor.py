"""Scope-separated mobile/backend correlation and controlled deep-link execution."""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from urllib.parse import urlsplit

from aegis.ai.agentic_os import AuthorizationEnvelope
from aegis.model.evidence import Canary, CanaryKind, EvidenceBundle, InteractionStep
from aegis.scheduler.profit import HuntOpportunity

from .cross_surface_intelligence import (
    CrossSurfaceIntelligenceAgent,
    CrossSurfaceKind,
    CrossSurfaceObservation,
    CrossSurfaceVerdict,
)
from .execution_errors import MissionBackendUnavailableError, MissionPrerequisiteError
from .mission_scheduler import MissionPlan, MissionTask, TaskState

BACKEND_CAPABILITIES = frozenset({
    "dynamic:identity-object-differential",
    "dynamic:graphql-auth-differential",
    "dynamic:websocket-state-differential",
})


@dataclass(frozen=True, slots=True)
class MobileBackendReference:
    endpoint: str
    callsite: str
    executor_capability: str
    evidence: tuple[str, ...]
    scope_confirmation_evidence: tuple[str, ...] = ()
    execution_payload: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        if urlsplit(self.endpoint).scheme not in {"http", "https", "ws", "wss"}:
            raise ValueError("mobile backend reference requires an HTTP or WebSocket endpoint")
        if self.executor_capability not in BACKEND_CAPABILITIES or not self.callsite or not self.evidence:
            raise ValueError("mobile backend reference is incomplete or unsupported")


@dataclass(frozen=True, slots=True)
class RegisteredMobileSurface:
    surface_id: str
    scope_digest: str
    artifact_kind: str
    artifact_sha256: str
    artifact_evidence: tuple[str, ...]
    backends: tuple[MobileBackendReference, ...]
    deep_links: tuple[str, ...] = ()
    oauth_client_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.artifact_kind not in {"android_apk", "ios_ipa"}:
            raise ValueError("mobile surface requires an APK or IPA")
        if len(self.artifact_sha256) != 64 or not self.artifact_evidence:
            raise ValueError("mobile surface requires a digest-bound authorized artifact")


@dataclass(frozen=True, slots=True)
class MobileBackendCorrelationOutcome:
    opportunities: tuple[HuntOpportunity, ...]
    mission_tasks: tuple[MissionTask, ...]
    verdicts: tuple[CrossSurfaceVerdict, ...]
    inferred_endpoints: tuple[str, ...]


class MobileBackendCorrelationExecutor:
    CAPABILITY = "jarvis:research:mobile-backend-correlation"

    def __init__(self, *, surfaces: Mapping[str, RegisteredMobileSurface], grant_verifier) -> None:
        self.surfaces = dict(surfaces)
        self.grant_verifier = grant_verifier
        self.agent = CrossSurfaceIntelligenceAgent()

    def __call__(self, task: MissionTask, plan: MissionPlan, authorization: AuthorizationEnvelope):
        grant = authorization.grant
        if (
            task.executor_capability != self.CAPABILITY or task.risk not in {"offline", "read_only"}
            or grant is None or authorization.scope_digest != plan.scope_digest
            or grant.scope_digest != plan.scope_digest or not grant.verify(self.grant_verifier)
            or not grant.human_approval
        ):
            raise PermissionError("mobile correlation requires an exact verified grant")
        surface = self.surfaces.get(str((task.payload or {}).get("mobile_surface_id") or ""))
        if surface is None:
            raise MissionPrerequisiteError("digest-bound mobile surface is not registered")
        if surface.scope_digest != plan.scope_digest:
            raise PermissionError("mobile artifact is bound to a different scope")
        opportunities = []
        tasks = []
        verdicts = []
        inferred = []
        for index, backend in enumerate(surface.backends):
            confirmed = bool(backend.scope_confirmation_evidence)
            observation_id = "mobile-backend:" + sha256(
                f"{surface.artifact_sha256}\x1f{backend.endpoint}\x1f{backend.callsite}".encode()
            ).hexdigest()[:20]
            evidence = tuple(dict.fromkeys((
                *surface.artifact_evidence, *backend.evidence,
                *backend.scope_confirmation_evidence,
                f"artifact-sha256:{surface.artifact_sha256}",
            )))
            observation = CrossSurfaceObservation(
                observation_id, CrossSurfaceKind.MOBILE_BACKEND,
                f"{surface.artifact_kind}://{surface.artifact_sha256}", backend.endpoint,
                backend.executor_capability, authorized_source=True,
                authorized_target=confirmed, evidence=evidence,
            )
            verdicts.append(self.agent.evaluate(observation))
            if not confirmed:
                inferred.append(backend.endpoint)
                continue
            opportunity_id = "opportunity:" + observation_id
            opportunities.append(HuntOpportunity(
                opportunity_id,
                asset_id=f"mobile-backend:{sha256(backend.endpoint.encode()).hexdigest()[:16]}",
                asset_kind="api",
                asset_locator=backend.endpoint,
                scope_digest=plan.scope_digest,
                authorization_id=plan.authorization_id,
                attack_surface="mobile_backend",
                weakness_family="authorization",
                prerequisite_state=("ready" if backend.execution_payload
                                    else "controlled_fixture_required"),
                estimated_payout_usd=None,
                provenance=evidence,
                metadata={
                    "mobile_surface_id": surface.surface_id,
                    "executor_capability": backend.executor_capability,
                    "deep_links": surface.deep_links,
                    "oauth_client_ids": surface.oauth_client_ids,
                },
            ))
            tasks.append(MissionTask(
                task_id=f"{task.task_id}:backend:{index}",
                agent_role="authorization",
                action="execute scope-confirmed mobile backend differential",
                state=(TaskState.PENDING if backend.execution_payload
                       else TaskState.WAITING_FOR_PREREQUISITE),
                payload=dict(backend.execution_payload or {}),
                opportunity_id=opportunity_id,
                asset_id=opportunities[-1].asset_id,
                asset_kind="api",
                asset_locator=backend.endpoint,
                executor_capability=backend.executor_capability,
                risk="controlled_state_change",
                prerequisites=("controlled_identity_fixture",),
                expected_requests=int((backend.execution_payload or {}).get("expected_requests", 0)),
                evidence_required=("mobile_callsite", "scope_confirmation", "canonical_evidence"),
                idempotency_key=f"{observation_id}:{backend.executor_capability}",
            ))
        return MobileBackendCorrelationOutcome(
            tuple(opportunities), tuple(tasks), tuple(verdicts), tuple(inferred),
        )

    def runtime_executors(self) -> dict[str, object]:
        return {self.CAPABILITY: self}


@dataclass(frozen=True, slots=True)
class RegisteredDeepLinkExperiment:
    experiment_id: str
    scope_digest: str
    package: str
    control_uri: str
    probe_uri: str
    synthetic_account: bool
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.package or not self.control_uri or not self.probe_uri or not self.evidence:
            raise ValueError("deep-link experiment registration is incomplete")
        if not self.synthetic_account:
            raise ValueError("deep-link execution requires a synthetic account")


@dataclass(frozen=True, slots=True)
class DeepLinkCapture:
    handled: bool
    before_state_digest: str
    after_state_digest: str
    user_confirmation_observed: bool
    output_digest: str
    evidence: tuple[str, ...]


StateReader = Callable[[], tuple[str, bool]]
Runner = Callable[[Sequence[str]], tuple[int, str]]


class AndroidAdbDeepLinkBackend:
    """Bounded argv-only adapter for an operator-controlled Android test device."""

    def __init__(self, *, device_serial: str, state_reader: StateReader,
                 runner: Runner | None = None, adb_path: str = "adb") -> None:
        if not device_serial:
            raise ValueError("controlled Android device serial is required")
        self.device_serial = device_serial
        self.state_reader = state_reader
        self.runner = runner or self._run
        self.adb_path = adb_path

    def execute(self, experiment: RegisteredDeepLinkExperiment, uri: str) -> DeepLinkCapture:
        before, _ = self.state_reader()
        command = (
            self.adb_path, "-s", self.device_serial, "shell", "am", "start", "-W",
            "-a", "android.intent.action.VIEW", "-d", uri, experiment.package,
        )
        code, output = self.runner(command)
        after, confirmation = self.state_reader()
        digest = sha256(output.encode()).hexdigest()
        return DeepLinkCapture(
            handled=(code == 0 and "Error:" not in output),
            before_state_digest=before,
            after_state_digest=after,
            user_confirmation_observed=confirmation,
            output_digest=digest,
            evidence=(f"adb-output-sha256:{digest}", f"device:{sha256(self.device_serial.encode()).hexdigest()}"),
        )

    @staticmethod
    def _run(command: Sequence[str]) -> tuple[int, str]:
        try:
            result = subprocess.run(
                list(command), capture_output=True, text=True, timeout=30, check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise MissionBackendUnavailableError(f"controlled ADB backend failed: {exc}") from exc
        return result.returncode, (result.stdout + result.stderr)[:4096]


@dataclass(frozen=True, slots=True)
class DeepLinkExecutionOutcome:
    control: DeepLinkCapture
    probe: DeepLinkCapture
    verdict: CrossSurfaceVerdict
    evidence: EvidenceBundle


class ControlledDeepLinkExecutor:
    CAPABILITY = "dynamic:deep-link-trust-differential"

    def __init__(self, backend, *, experiments: Mapping[str, RegisteredDeepLinkExperiment],
                 grant_verifier) -> None:
        self.backend = backend
        self.experiments = dict(experiments)
        self.grant_verifier = grant_verifier
        self.agent = CrossSurfaceIntelligenceAgent()

    def __call__(self, task, plan, authorization):
        grant = authorization.grant
        if (
            task.executor_capability != self.CAPABILITY or grant is None
            or authorization.scope_digest != plan.scope_digest
            or grant.scope_digest != plan.scope_digest or not grant.verify(self.grant_verifier)
            or not grant.state_change_allowed or not grant.human_approval
        ):
            raise PermissionError("deep-link execution requires an exact verified state-change grant")
        experiment = self.experiments.get(str((task.payload or {}).get("experiment_id") or ""))
        if experiment is None:
            raise MissionPrerequisiteError("controlled deep-link experiment is not registered")
        if experiment.scope_digest != plan.scope_digest:
            raise PermissionError("deep-link experiment is bound to another scope")
        try:
            control = self.backend.execute(experiment, experiment.control_uri)
            probe = self.backend.execute(experiment, experiment.probe_uri)
        except (MissionBackendUnavailableError, PermissionError):
            raise
        except Exception as exc:
            raise MissionBackendUnavailableError(f"deep-link backend failed: {exc}") from exc
        control_changed = control.before_state_digest != control.after_state_digest
        probe_changed = probe.before_state_digest != probe.after_state_digest
        observation = CrossSurfaceObservation(
            f"deep-link:{experiment.experiment_id}", CrossSurfaceKind.DEEP_LINK,
            experiment.probe_uri, experiment.package, "deep_link", True, True, True,
            control.handled, probe.handled, False, probe_changed, True,
            probe.user_confirmation_observed,
            tuple(dict.fromkeys((*experiment.evidence, *control.evidence, *probe.evidence,
                                 f"control-state-changed:{control_changed}"))),
        )
        verdict = self.agent.evaluate(observation)
        evidence = EvidenceBundle(
            steps=[
                InteractionStep(summary="controlled deep-link baseline",
                                response=f"handled={control.handled}; output={control.output_digest}"),
                InteractionStep(summary="sensitive deep-link probe",
                                response=(f"handled={probe.handled}; state-changed={probe_changed}; "
                                          f"confirmation={probe.user_confirmation_observed}")),
            ],
            canary=Canary(kind=CanaryKind.CONTROLLED_EVAL,
                          value=f"deep-link:{experiment.experiment_id}",
                          note="operator-controlled test app workflow"),
            observed=verdict.reason,
            expected="sensitive deep links require the registered confirmation and state policy",
            replay_ref=verdict.verdict_id,
            confidence=verdict.confidence,
            artifacts=list(verdict.evidence),
        )
        return DeepLinkExecutionOutcome(control, probe, verdict, evidence)

    def runtime_executors(self) -> dict[str, object]:
        return {self.CAPABILITY: self}


__all__ = [
    "AndroidAdbDeepLinkBackend", "ControlledDeepLinkExecutor", "DeepLinkCapture",
    "DeepLinkExecutionOutcome", "MobileBackendCorrelationExecutor",
    "MobileBackendCorrelationOutcome", "MobileBackendReference", "RegisteredDeepLinkExperiment",
    "RegisteredMobileSurface",
]
