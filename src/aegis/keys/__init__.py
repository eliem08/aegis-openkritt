"""Versioned key management with envelope encryption (Phase 5)."""

from .keyring import (
    EnvelopeEncryptor,
    KeyManagementError,
    KeyRevoked,
    KeyRing,
    KeyUnavailable,
    ManagedKey,
)

__all__ = [
    "EnvelopeEncryptor",
    "KeyManagementError",
    "KeyRevoked",
    "KeyRing",
    "KeyUnavailable",
    "ManagedKey",
]
