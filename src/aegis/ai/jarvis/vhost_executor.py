"""Read-only virtual-host routing differential for scope-confirmed hostnames."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256

from aegis.ai.agentic_os import AuthorizationEnvelope
from aegis.model.evidence import EvidenceBundle, InteractionStep

from .execution_errors import MissionPrerequisiteError
from .mission_scheduler import MissionPlan, MissionTask
from .scoped_http_executor import ScopedEgressHttpExecutor


@dataclass(frozen=True, slots=True)
class ConfirmedVHost:
    hostname: str
    scope_evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.hostname or "://" in self.hostname or not self.scope_evidence:
            raise ValueError("vhost candidate requires a confirmed bare hostname")


@dataclass(frozen=True, slots=True)
class RegisteredVHostExperiment:
    experiment_id: str
    scope_digest: str
    authorized_ip: str
    scheme: str
    path: str
    candidates: tuple[ConfirmedVHost, ...]
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        address = ipaddress.ip_address(self.authorized_ip)
        if not address.is_global:
            raise ValueError("vhost experiment requires an authorized public IP")
        if self.scheme not in {"http", "https"} or not self.path.startswith("/"):
            raise ValueError("vhost experiment scheme or path is invalid")
        if not self.candidates or not self.evidence:
            raise ValueError("vhost experiment requires candidates and provenance")


@dataclass(frozen=True, slots=True)
class VHostObservation:
    hostname: str
    status_code: int
    response_digest: str
    pinned_ip: str
    differs_from_baseline: bool
    evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class VHostExecutionOutcome:
    baseline_digest: str
    observations: tuple[VHostObservation, ...]
    evidence: tuple[EvidenceBundle, ...]


class ScopedVHostRoutingExecutor:
    CAPABILITY = "dynamic:vhost-routing-differential"

    def __init__(self, http: ScopedEgressHttpExecutor, *, experiments: Mapping[str, RegisteredVHostExperiment],
                 grant_verifier) -> None:
        self.http = http
        self.experiments = dict(experiments)
        self.grant_verifier = grant_verifier

    def __call__(self, task: MissionTask, plan: MissionPlan, authorization: AuthorizationEnvelope):
        grant = authorization.grant
        if (
            task.executor_capability != self.CAPABILITY or task.risk != "read_only"
            or grant is None or authorization.scope_digest != plan.scope_digest
            or grant.scope_digest != plan.scope_digest or not grant.verify(self.grant_verifier)
            or not grant.network_allowed or not grant.human_approval
        ):
            raise PermissionError("vhost execution requires an exact verified read-only grant")
        experiment = self.experiments.get(str((task.payload or {}).get("experiment_id") or ""))
        if experiment is None:
            raise MissionPrerequisiteError("scope-confirmed vhost experiment is not registered")
        if experiment.scope_digest != plan.scope_digest:
            raise PermissionError("vhost experiment is bound to a different scope")
        baseline = self.http.request(
            "GET", f"{experiment.scheme}://{experiment.authorized_ip}{experiment.path}",
            authorization=authorization,
        )
        if baseline.pinned_ip != experiment.authorized_ip:
            raise PermissionError("vhost baseline did not pin to the registered IP")
        baseline_digest = sha256(baseline.body).hexdigest()
        observations = []
        bundles = []
        for candidate in experiment.candidates:
            response = self.http.request(
                "GET", f"{experiment.scheme}://{candidate.hostname}{experiment.path}",
                authorization=authorization,
            )
            if response.pinned_ip != experiment.authorized_ip:
                raise PermissionError(
                    f"scope-confirmed hostname did not resolve to registered IP: {candidate.hostname}"
                )
            digest = sha256(response.body).hexdigest()
            observation = VHostObservation(
                candidate.hostname, response.status_code, digest, response.pinned_ip,
                digest != baseline_digest or response.status_code != baseline.status_code,
                tuple(dict.fromkeys((*experiment.evidence, *candidate.scope_evidence,
                                     f"response-sha256:{digest}"))),
            )
            observations.append(observation)
            bundles.append(EvidenceBundle(
                steps=[
                    InteractionStep(summary="authorized IP routing baseline",
                                    response=f"status={baseline.status_code}; sha256={baseline_digest}"),
                    InteractionStep(summary="scope-confirmed hostname routing probe",
                                    request=f"hostname={candidate.hostname}; path={experiment.path}",
                                    response=f"status={response.status_code}; sha256={digest}"),
                ],
                observed=("hostname produced distinct routing behavior"
                          if observation.differs_from_baseline
                          else "hostname matched the authorized IP baseline"),
                expected="only scope-confirmed hostnames resolving to the registered IP are compared",
                replay_ref=f"vhost:{sha256((experiment.experiment_id + candidate.hostname).encode()).hexdigest()[:20]}",
                confidence=0.85 if observation.differs_from_baseline else 0.75,
                artifacts=list(observation.evidence),
            ))
        return VHostExecutionOutcome(baseline_digest, tuple(observations), tuple(bundles))

    def runtime_executors(self) -> dict[str, object]:
        return {self.CAPABILITY: self}


__all__ = [
    "ConfirmedVHost", "RegisteredVHostExperiment", "ScopedVHostRoutingExecutor",
    "VHostExecutionOutcome", "VHostObservation",
]
