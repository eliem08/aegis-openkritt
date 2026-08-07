"""Signed worker identities and typed capability queues (Phase 5 §Distributed
coordination).

A worker claims typed queues *by capability*: a browser worker cannot pull OAST or
template-scan tasks unless its signed identity declares those capabilities. The
control plane issues short-lived, signed identities (server-authenticated to the
worker), and the worker proves possession of its own key over a fresh nonce
(worker-authenticated to the server) — mutual authentication with no long-lived
shared secret in flight.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

# Queue -> the capability a worker identity must declare to claim it.
QUEUE_CAPABILITIES = {
    "discovery": "discovery",
    "active": "active",
    "template": "template",
    "oast": "oast",
    "browser": "browser",
}


class WorkerAuthError(RuntimeError):
    pass


class InvalidWorkerIdentity(WorkerAuthError):
    pass


class WorkerIdentityExpired(WorkerAuthError):
    pass


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class WorkerIdentity:
    worker_id: str
    tenant_id: str | None            # None = a shared/system worker
    capabilities: tuple[str, ...]
    worker_key_id: str               # names the worker's own signing key
    issued_at: datetime
    expires_at: datetime
    issuer_key_id: str
    signature: str | None = None

    def signing_payload(self) -> dict:
        return {
            "worker_id": self.worker_id, "tenant_id": self.tenant_id,
            "capabilities": sorted(self.capabilities), "worker_key_id": self.worker_key_id,
            "issued_at": self.issued_at.isoformat(), "expires_at": self.expires_at.isoformat(),
        }


class WorkerIdentityIssuer:
    """The control plane: issues short-lived signed worker identities."""

    def __init__(self, verifier, *, key_id: str) -> None:
        self._verifier = verifier
        self._key_id = key_id

    def issue(self, worker_id: str, *, capabilities, worker_key_id: str,
              tenant_id: str | None = None, ttl_seconds: int = 900,
              now: datetime | None = None) -> WorkerIdentity:
        now = now or _now()
        identity = WorkerIdentity(
            worker_id=worker_id, tenant_id=tenant_id,
            capabilities=tuple(sorted(set(capabilities))), worker_key_id=worker_key_id,
            issued_at=now, expires_at=now + timedelta(seconds=ttl_seconds),
            issuer_key_id=self._key_id)
        signature = self._verifier.sign(identity.signing_payload(), self._key_id)
        return WorkerIdentity(**{**vars(identity), "signature": signature})


class WorkerAuthority:
    """Verifies worker identities and gates typed-queue claims."""

    def __init__(self, issuer_verifier, *, worker_verifier=None,
                 clock=None) -> None:
        self._issuer = issuer_verifier
        self._worker = worker_verifier
        self._clock = clock or _now

    def verify(self, identity: WorkerIdentity) -> None:
        """Server-authenticated: the identity was signed by the control plane and
        has not expired."""
        if not identity.signature:
            raise InvalidWorkerIdentity("worker identity is unsigned")
        if not self._issuer.verify(identity.signing_payload(), identity.signature, identity.issuer_key_id):
            raise InvalidWorkerIdentity("worker identity signature is invalid")
        if self._clock() >= identity.expires_at:
            raise WorkerIdentityExpired(identity.worker_id)

    def can_claim(self, identity: WorkerIdentity, queue: str) -> bool:
        """A worker may claim a queue only if its verified identity declares the
        matching capability."""
        try:
            self.verify(identity)
        except WorkerAuthError:
            return False
        required = QUEUE_CAPABILITIES.get(queue)
        return required is not None and required in identity.capabilities

    def authenticate(self, identity: WorkerIdentity, *, nonce: str, worker_proof: str) -> bool:
        """Mutual: verify the issuer's signature AND the worker's proof of its own
        key over a fresh nonce."""
        try:
            self.verify(identity)
        except WorkerAuthError:
            return False
        if self._worker is None:
            return False
        payload = {"worker_id": identity.worker_id, "nonce": nonce}
        return bool(self._worker.verify(payload, worker_proof, identity.worker_key_id))


def worker_proof(worker_verifier, *, worker_id: str, worker_key_id: str, nonce: str) -> str:
    """The worker side of the handshake: sign a fresh nonce with the worker key."""
    return worker_verifier.sign({"worker_id": worker_id, "nonce": nonce}, worker_key_id)
