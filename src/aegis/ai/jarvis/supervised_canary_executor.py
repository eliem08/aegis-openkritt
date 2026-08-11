"""Minimal read-only production executor for an operator-selected live canary."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from urllib.parse import urlsplit

from aegis.ai.agentic_os import AuthorizationEnvelope
from aegis.model.evidence import EvidenceBundle, InteractionStep

from .mission_scheduler import MissionPlan, MissionTask
from .scoped_http_executor import ScopedEgressHttpExecutor

CAPABILITY = "jarvis:research:supervised_http_observation"


@dataclass(frozen=True, slots=True)
class SupervisedCanaryOutcome:
    method: str
    target: str
    status_code: int
    response_digest: str
    response_bytes: int
    final_url: str
    redirects: int
    evidence: EvidenceBundle


class SupervisedHttpCanaryExecutor:
    """Make one exact, grant-bound GET/HEAD/OPTIONS request and retain no response body."""

    def __init__(self, http: ScopedEgressHttpExecutor, *, grant_verifier) -> None:
        self.http = http
        self.grant_verifier = grant_verifier

    def __call__(
        self, task: MissionTask, plan: MissionPlan, authorization: AuthorizationEnvelope,
    ) -> SupervisedCanaryOutcome:
        grant = authorization.grant
        payload = task.payload or {}
        method = str(payload.get("method") or "").upper()
        target = str(payload.get("url") or "")
        parts = urlsplit(target)
        if task.executor_capability != CAPABILITY or task.risk != "read_only":
            raise PermissionError("supervised canary executor accepts only its read-only capability")
        if method not in {"GET", "HEAD", "OPTIONS"}:
            raise PermissionError("supervised canary method is not read-only")
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
            raise PermissionError("supervised canary requires an exact HTTPS destination")
        if parts.hostname.casefold() != task.asset_locator.casefold():
            raise PermissionError("supervised canary destination differs from the selected asset")
        if task.expected_requests != 1 or task.expected_cost_usd < 0:
            raise PermissionError("supervised canary task must consume exactly one request")
        if (
            grant is None
            or not grant.verify(self.grant_verifier)
            or not grant.network_allowed
            or grant.state_change_allowed
            or grant.human_approval
            or target not in grant.allowed_destinations
            or method not in grant.allowed_methods
        ):
            raise PermissionError("supervised canary requires an exact, unexpired read-only grant")

        response = self.http.request(method, target, authorization=authorization)
        digest = sha256(response.body).hexdigest()
        evidence = EvidenceBundle(
            steps=[InteractionStep(
                summary="bounded supervised read-only HTTP observation",
                request=f"{method} {target}",
                response=(
                    f"status={response.status_code}; bytes={len(response.body)}; "
                    f"sha256={digest}; redirects={response.redirects}"
                ),
            )],
            observed="authorized response metadata and body digest captured",
            expected="one exact in-scope read-only request with no state change",
            replay_ref=f"canary:{digest[:20]}",
            confidence=1.0,
            artifacts=[f"response-sha256:{digest}", f"final-url:{response.final_url}"],
        )
        return SupervisedCanaryOutcome(
            method, target, response.status_code, digest, len(response.body),
            response.final_url, response.redirects, evidence,
        )

    def runtime_executors(self) -> dict[str, object]:
        return {CAPABILITY: self}


__all__ = ["CAPABILITY", "SupervisedCanaryOutcome", "SupervisedHttpCanaryExecutor"]
