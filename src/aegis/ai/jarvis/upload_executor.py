"""Safe synthetic upload workflow execution with identity and private-OAST controls."""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from urllib.parse import urljoin

from aegis.ai.agentic_os import AuthorizationEnvelope
from aegis.model.evidence import Canary, CanaryKind, EvidenceBundle, InteractionStep

from .execution_errors import MissionObservationPending, MissionPrerequisiteError
from .identity_fixtures import ControlledIdentityFixtureSet, FixtureKind, FixtureProtocol
from .mission_scheduler import MissionPlan, MissionTask
from .scoped_http_executor import ScopedEgressHttpExecutor

SAFE_UPLOAD_SUFFIXES = frozenset({".txt", ".json"})
MAX_FIXTURE_BYTES = 16_384


@dataclass(frozen=True, slots=True)
class UploadWorkflowVerdict:
    cross_user_access: bool
    unexpected_server_fetch: bool
    worker_state_mismatch: bool
    upload_id_digest: str
    evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UploadWorkflowExecutionOutcome:
    verdict: UploadWorkflowVerdict
    evidence: EvidenceBundle


class ScopedUploadWorkflowExecutor:
    CAPABILITY = "dynamic:upload-workflow-differential"

    def __init__(
        self, http: ScopedEgressHttpExecutor, *, fixture_sets, credential_resolver,
        grant_verifier, oast_service, oast_principal,
    ) -> None:
        self.http = http
        self.fixture_sets: Mapping[str, ControlledIdentityFixtureSet] = dict(fixture_sets)
        self.credential_resolver = credential_resolver
        self.grant_verifier = grant_verifier
        self.oast_service = oast_service
        self.oast_principal = oast_principal

    def __call__(self, task: MissionTask, plan: MissionPlan, authorization: AuthorizationEnvelope):
        self._authorize(task, plan, authorization)
        payload = task.payload or {}
        fixtures = self.fixture_sets.get(str(payload.get("fixture_set_id") or ""))
        if fixtures is None:
            raise MissionPrerequisiteError("controlled upload fixture set is not registered")
        if fixtures.scope_digest != plan.scope_digest:
            raise PermissionError("upload fixtures are bound to a different mission scope")
        try:
            binding = fixtures.require_protocol(FixtureProtocol.HTTP)
            owner = fixtures.fixtures[FixtureKind.OWNER]
            peer = fixtures.fixtures[FixtureKind.FOREIGN_SAME_ROLE]
            owner_headers = dict(self.credential_resolver(owner.credential.reference))
            peer_headers = dict(self.credential_resolver(peer.credential.reference))
            session_ref = str(payload["oast_session_ref"])
            canary = str(payload["canary"])
            filename = str(payload.get("filename") or "aegis-fixture.txt")
        except Exception as exc:
            raise MissionPrerequisiteError(
                "upload execution requires owner/peer credentials, HTTP binding, canary, and OAST session"
            ) from exc
        if not owner_headers or not peer_headers or not canary:
            raise MissionPrerequisiteError("upload controls require two identities and a canary")
        suffix = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if suffix not in SAFE_UPLOAD_SUFFIXES or "/" in filename or "\\" in filename:
            raise MissionPrerequisiteError("upload fixture filename is not in the safe text allowlist")
        content = f"AEGIS SAFE SYNTHETIC UPLOAD\nmarker={canary}\n".encode()
        if len(content) > MAX_FIXTURE_BYTES:
            raise MissionPrerequisiteError("upload fixture exceeded the safe size limit")
        probe = self.oast_service.plant_probe(session_ref, self.oast_principal)
        upload_body = json.dumps({
            "filename": filename,
            "content_type": "text/plain" if suffix == ".txt" else "application/json",
            "content_base64": base64.b64encode(content).decode("ascii"),
            "metadata_url": "https://" + probe.address,
        }, sort_keys=True, separators=(",", ":")).encode()
        upload = self._request(
            binding.endpoint, str(payload.get("upload_path") or "/uploads"), "POST",
            owner_headers, upload_body, authorization,
        )
        try:
            upload_doc = json.loads(upload.body)
            upload_id = str(upload_doc["upload_id"])
        except (json.JSONDecodeError, KeyError, TypeError, UnicodeDecodeError) as exc:
            raise MissionPrerequisiteError("upload response did not return an upload_id") from exc
        if not upload_id or len(upload_id) > 256:
            raise MissionPrerequisiteError("upload_id is empty or exceeded the safe limit")
        paths = {
            name: self._render(str(payload[name]), upload_id)
            for name in ("status_path", "retrieval_path", "renderer_path")
        }
        status = self._request(
            binding.endpoint, paths["status_path"], "GET", owner_headers, b"", authorization,
        )
        owner_get = self._request(
            binding.endpoint, paths["retrieval_path"], "GET", owner_headers, b"", authorization,
        )
        peer_get = self._request(
            binding.endpoint, paths["retrieval_path"], "GET", peer_headers, b"", authorization,
        )
        rendered = self._request(
            binding.endpoint, paths["renderer_path"], "GET", owner_headers, b"", authorization,
        )
        try:
            status_doc = json.loads(status.body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise MissionPrerequisiteError("upload worker status was not JSON") from exc
        terminal = str(status_doc.get("worker_state") or "")
        if terminal not in {"processed", "failed"}:
            raise MissionObservationPending(f"upload worker remains non-terminal: {terminal or 'unknown'}")
        callbacks = tuple(
            row for row in self.oast_service.poll(session_ref, self.oast_principal)
            if row.host == probe.address
        )
        owner_has_canary = canary.encode() in owner_get.body
        peer_has_canary = canary.encode() in peer_get.body
        renderer_has_canary = canary.encode() in rendered.body
        expected_states = dict(payload.get("expected_states") or {
            "storage_state": "stored", "worker_state": "processed", "renderer_state": "rendered",
        })
        mismatch = (
            any(str(status_doc.get(key)) != str(value) for key, value in expected_states.items())
            or not owner_has_canary or not renderer_has_canary
        )
        upload_digest = sha256(upload_id.encode()).hexdigest()
        artifacts = tuple(dict.fromkeys((
            *binding.evidence, f"upload-id-sha256:{upload_digest}",
            f"status-sha256:{sha256(status.body).hexdigest()}",
            f"owner-retrieval-sha256:{sha256(owner_get.body).hexdigest()}",
            f"peer-retrieval-sha256:{sha256(peer_get.body).hexdigest()}",
            f"renderer-sha256:{sha256(rendered.body).hexdigest()}",
            f"oast-callbacks:{len(callbacks)}",
        )))
        verdict = UploadWorkflowVerdict(peer_has_canary, bool(callbacks), mismatch,
                                        upload_digest, artifacts)
        evidence = EvidenceBundle(
            steps=[
                InteractionStep(summary="uploaded safe synthetic text fixture",
                                response=f"status={upload.status_code}; id-sha256={upload_digest}"),
                InteractionStep(summary="verified storage/parser/worker state",
                                response=f"status={status.status_code}; terminal={terminal}"),
                InteractionStep(summary="compared owner and foreign retrieval",
                                response=(f"owner-marker={owner_has_canary}; "
                                          f"foreign-marker={peer_has_canary}")),
                InteractionStep(summary="verified renderer and private OAST negative control",
                                response=(f"renderer-marker={renderer_has_canary}; "
                                          f"callbacks={len(callbacks)}")),
            ],
            canary=Canary(kind=CanaryKind.SYNTHETIC_MARKER, value=canary,
                          note="safe text-only upload marker"),
            observed=(
                "upload workflow violation observed" if any((peer_has_canary, callbacks, mismatch))
                else "upload workflow preserved identity, worker, renderer, and URL-fetch controls"
            ),
            expected="foreign identities receive no marker and processing remains internally consistent",
            replay_ref=f"upload:{upload_digest[:20]}",
            confidence=0.97 if any((peer_has_canary, callbacks, mismatch)) else 0.9,
            artifacts=list(artifacts),
        )
        return UploadWorkflowExecutionOutcome(verdict, evidence)

    def _authorize(self, task, plan, authorization):
        grant = authorization.grant
        if (
            task.executor_capability != self.CAPABILITY or grant is None
            or authorization.scope_digest != plan.scope_digest
            or grant.scope_digest != plan.scope_digest
            or not grant.verify(self.grant_verifier) or not grant.network_allowed
            or not grant.state_change_allowed or not grant.human_approval
        ):
            raise PermissionError("upload execution requires an exact verified state-change grant")

    def _request(self, endpoint, path, method, headers, body, authorization):
        if not path.startswith("/") or path.startswith("//"):
            raise MissionPrerequisiteError("upload workflow paths must be absolute local paths")
        return self.http.request(
            method, urljoin(endpoint, path), authorization=authorization,
            headers={"content-type": "application/json", **headers}, body=body,
        )

    @staticmethod
    def _render(path, upload_id):
        return path.replace("{upload_id}", upload_id)

    def runtime_executors(self) -> dict[str, object]:
        return {self.CAPABILITY: self}


__all__ = [
    "ScopedUploadWorkflowExecutor", "UploadWorkflowExecutionOutcome", "UploadWorkflowVerdict",
]
