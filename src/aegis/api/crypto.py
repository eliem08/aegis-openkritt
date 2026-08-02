"""Encryption at rest for sensitive stored columns (Master Prompt §12).

The audit trail and the authorization JSON can contain sensitive material
(scope, identities, decision detail). When ``AEGIS_ENCRYPTION_KEY`` is set, the
repositories encrypt those columns with Fernet (AES-128-CBC + HMAC, authenticated)
before writing and decrypt on read. Without a key the ``NullEncryptor`` stores
plaintext (backwards compatible). The key never appears in logs.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class Encryptor(Protocol):
    def encrypt(self, text: str) -> str: ...
    def decrypt(self, text: str) -> str: ...


class NullEncryptor:
    """No-op (plaintext). The default when no key is configured."""

    def encrypt(self, text: str) -> str:
        return text

    def decrypt(self, text: str) -> str:
        return text


class FernetEncryptor:
    """Authenticated symmetric encryption via ``cryptography.fernet``."""

    def __init__(self, key: str | bytes) -> None:
        from cryptography.fernet import Fernet

        self._fernet = Fernet(key.encode("ascii") if isinstance(key, str) else key)

    def encrypt(self, text: str) -> str:
        return self._fernet.encrypt(text.encode("utf-8")).decode("ascii")

    def decrypt(self, text: str) -> str:
        return self._fernet.decrypt(text.encode("ascii")).decode("utf-8")


def generate_key() -> str:
    """A fresh Fernet key (urlsafe base64). Store it in a secrets manager."""
    from cryptography.fernet import Fernet

    return Fernet.generate_key().decode("ascii")


def build_encryptor(key: str | None) -> Encryptor:
    return FernetEncryptor(key) if key else NullEncryptor()
