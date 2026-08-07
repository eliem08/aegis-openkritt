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


# --- Ed25519 (asymmetric) -------------------------------------------------
#
# The production-grade choice (Master Prompt §8 / P0 #8): the control plane
# signs with a *private* key; the agent verifies with a *public* key it cannot
# use to forge. Requires the ``cryptography`` package.

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    _HAS_ED25519 = True
except ImportError:  # pragma: no cover - crypto not installed
    _HAS_ED25519 = False


def _require_crypto() -> None:
    if not _HAS_ED25519:
        raise RuntimeError("Ed25519 signing requires the 'cryptography' package")


def _to_public_key(value) -> Ed25519PublicKey:
    if isinstance(value, Ed25519PublicKey):
        return value
    raw = bytes.fromhex(value) if isinstance(value, str) else bytes(value)
    return Ed25519PublicKey.from_public_bytes(raw)


class Ed25519SignatureVerifier:
    """Verifies Ed25519 signatures with per-``key_id`` public keys.

    Public keys may be raw 32-byte values, hex strings, or ``Ed25519PublicKey``
    objects. Holds no private material — it can verify but never forge.
    """

    def __init__(self, public_keys: dict[str, bytes | str | Ed25519PublicKey]) -> None:
        _require_crypto()
        if not public_keys:
            raise ValueError("at least one public key is required")
        self._keys: dict[str, Ed25519PublicKey] = {
            kid: _to_public_key(pk) for kid, pk in public_keys.items()
        }

    def verify(self, payload: dict[str, Any], signature: str | None, key_id: str | None) -> bool:
        if not signature or not key_id:
            return False
        public_key = self._keys.get(key_id)
        if public_key is None:
            return False
        try:
            sig = bytes.fromhex(signature)
        except ValueError:
            return False
        try:
            public_key.verify(sig, canonical_bytes(payload))
            return True
        except InvalidSignature:
            return False
        except Exception:  # any crypto error => reject (fail closed)
            return False


class Ed25519Signer:
    """Signs authorization payloads with an Ed25519 private key (control plane)."""

    def __init__(self, private_key: bytes | str | Ed25519PrivateKey, key_id: str) -> None:
        _require_crypto()
        if isinstance(private_key, Ed25519PrivateKey):
            self._key = private_key
        else:
            raw = bytes.fromhex(private_key) if isinstance(private_key, str) else bytes(private_key)
            self._key = Ed25519PrivateKey.from_private_bytes(raw)
        self.key_id = key_id

    @classmethod
    def generate(cls, key_id: str) -> Ed25519Signer:
        _require_crypto()
        return cls(Ed25519PrivateKey.generate(), key_id)

    def sign(self, payload: dict[str, Any]) -> str:
        return self._key.sign(canonical_bytes(payload)).hex()

    def public_key_hex(self) -> str:
        return self._key.public_key().public_bytes_raw().hex()

    def private_key_hex(self) -> str:
        return self._key.private_bytes_raw().hex()

    def verifier(self) -> Ed25519SignatureVerifier:
        return Ed25519SignatureVerifier({self.key_id: self._key.public_key()})
