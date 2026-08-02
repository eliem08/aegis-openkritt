"""Authorization signature verification (Master Prompt §4).

An authorization object must be *signed and unexpired* before any active action
is permitted. Signing proves the object came from the control plane and was not
tampered with in transit or at rest.

The default verifier here is HMAC-SHA256 with a shared secret held by the
control plane — stdlib-only, so the safety core has no hard crypto dependency.
For production, swap in an asymmetric verifier (e.g. Ed25519 via
``cryptography``) that implements the same :class:`SignatureVerifier` protocol,
so the agent verifies with a public key it cannot use to forge.

Canonicalisation is deterministic (sorted keys, tight separators, ISO-8601
datetimes) so signer and verifier always hash identical bytes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Protocol, runtime_checkable


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Deterministic JSON encoding used as the signing input.

    The ``signature`` and ``signing_key_id`` fields are excluded so an object
    can carry its own signature without the signature covering itself.
    """
    filtered = {k: v for k, v in payload.items() if k not in ("signature", "signing_key_id")}
    return json.dumps(
        filtered, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")


@runtime_checkable
class SignatureVerifier(Protocol):
    """Anything that can confirm a payload's signature is authentic."""

    def verify(self, payload: dict[str, Any], signature: str | None, key_id: str | None) -> bool:
        ...


class HmacSignatureVerifier:
    """HMAC-SHA256 verifier backed by an in-memory ``key_id -> secret`` map."""

    def __init__(self, keys: dict[str, bytes | str]) -> None:
        if not keys:
            raise ValueError("at least one signing key is required")
        self._keys: dict[str, bytes] = {
            kid: (secret.encode("utf-8") if isinstance(secret, str) else secret)
            for kid, secret in keys.items()
        }

    def sign(self, payload: dict[str, Any], key_id: str) -> str:
        secret = self._keys.get(key_id)
        if secret is None:
            raise KeyError(f"unknown signing key_id: {key_id!r}")
        return hmac.new(secret, canonical_bytes(payload), hashlib.sha256).hexdigest()

    def verify(self, payload: dict[str, Any], signature: str | None, key_id: str | None) -> bool:
        if not signature or not key_id:
            return False
        secret = self._keys.get(key_id)
        if secret is None:
            return False
        expected = hmac.new(secret, canonical_bytes(payload), hashlib.sha256).hexdigest()
        # Constant-time comparison to avoid leaking the signature via timing.
        return hmac.compare_digest(expected, signature)


class RejectAllVerifier:
    """The fail-closed default when no verifier is configured.

    Every signature is rejected. An engine constructed with
    ``require_signature=True`` (the default) and this verifier will refuse all
    active actions — you must supply a real verifier to operate.
    """

    def verify(self, payload: dict[str, Any], signature: str | None, key_id: str | None) -> bool:
        return False
