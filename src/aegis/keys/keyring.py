"""Versioned key management (Phase 5 §Key and secret management).

Replaces flat ``.env`` secrets with a rotate-able key ring. Data is sealed in an
**envelope** that names the key that sealed it (``key_id:ciphertext``), so:

* multiple key versions verify/decrypt at once (overlapping windows), so rotation
  never makes existing data unavailable;
* :meth:`EnvelopeEncryptor.rewrap` re-seals old data under the active key without
  a plaintext round-trip leaving the process;
* a **missing or revoked key fails closed** with a diagnostic — it never falls
  back to plaintext.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from aegis.api.crypto import FernetEncryptor


class KeyManagementError(RuntimeError):
    pass


class KeyUnavailable(KeyManagementError):
    """The key that sealed an envelope is not present (fail closed)."""


class KeyRevoked(KeyManagementError):
    """The key that sealed an envelope has been revoked (fail closed)."""


@dataclass
class ManagedKey:
    key_id: str
    encryptor: FernetEncryptor
    created_at: datetime
    revoked: bool = False


class KeyRing:
    def __init__(self) -> None:
        self._keys: dict[str, ManagedKey] = {}
        self._active_id: str | None = None

    def add(self, key_id: str, material: str, *, activate: bool = False) -> ManagedKey:
        if key_id in self._keys:
            raise KeyManagementError(f"key {key_id!r} already exists")
        key = ManagedKey(key_id, FernetEncryptor(material), datetime.now(UTC))
        self._keys[key_id] = key
        if activate or self._active_id is None:
            self._active_id = key_id
        return key

    def rotate(self, key_id: str, material: str) -> ManagedKey:
        """Add a new key and make it active; older keys remain for decryption."""
        return self.add(key_id, material, activate=True)

    def revoke(self, key_id: str) -> None:
        key = self._keys.get(key_id)
        if key is None:
            raise KeyUnavailable(key_id)
        key.revoked = True
        if self._active_id == key_id:
            # Never leave the ring pointing at a revoked active key.
            self._active_id = next((k.key_id for k in self._keys.values() if not k.revoked), None)

    @property
    def active(self) -> ManagedKey:
        if self._active_id is None:
            raise KeyUnavailable("no active key configured")
        return self._keys[self._active_id]

    def get(self, key_id: str) -> ManagedKey:
        key = self._keys.get(key_id)
        if key is None:
            raise KeyUnavailable(key_id)                 # fail closed — never plaintext
        if key.revoked:
            raise KeyRevoked(key_id)
        return key

    def key_ids(self) -> list[str]:
        return list(self._keys)


class EnvelopeEncryptor:
    """An :class:`Encryptor` whose ciphertext carries the sealing key id."""

    def __init__(self, keyring: KeyRing) -> None:
        self._ring = keyring

    def encrypt(self, text: str) -> str:
        key = self._ring.active
        return f"{key.key_id}:{key.encryptor.encrypt(text)}"

    def decrypt(self, envelope: str) -> str:
        key_id, ciphertext = self._split(envelope)
        return self._ring.get(key_id).encryptor.decrypt(ciphertext)   # raises if missing/revoked

    def rewrap(self, envelope: str) -> str:
        """Re-seal under the active key (rotation) without exposing plaintext."""
        plaintext = self.decrypt(envelope)
        return self.encrypt(plaintext)

    def adopt(self, ciphertext: str, key_id: str) -> str:
        """Attach a key id to pre-existing ciphertext sealed by that key."""
        self._ring.get(key_id)      # verify the key is present + active
        return f"{key_id}:{ciphertext}"

    @staticmethod
    def key_id_of(envelope: str) -> str:
        return EnvelopeEncryptor._split(envelope)[0]

    @staticmethod
    def _split(envelope: str) -> tuple[str, str]:
        if ":" not in envelope:
            raise KeyManagementError("envelope has no key identifier")
        key_id, ciphertext = envelope.split(":", 1)
        return key_id, ciphertext
