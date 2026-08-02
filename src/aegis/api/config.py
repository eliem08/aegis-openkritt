"""Control-plane configuration and identity.

The control plane is itself a security-sensitive surface: it holds the signing
keys used to verify authorization objects and it decides who may request
decisions, grant approvals, or fire the kill switch. Configuration is therefore
loaded explicitly (from env or injected in tests) and defaults fail closed —
signatures required, authentication on.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Mapping

from aegis.policy import (
    Ed25519SignatureVerifier,
    HmacSignatureVerifier,
    RejectAllVerifier,
    SignatureVerifier,
)

TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off", ""}


class Role(IntEnum):
    """Roles. AGENT/OPERATOR are the ordered scan roles (operator ⊇ agent).
    SYSTEM_ADMIN is a separate operational role that **cannot execute scans**."""

    AGENT = 1
    OPERATOR = 2
    SYSTEM_ADMIN = 3

    @classmethod
    def parse(cls, value: str | int) -> "Role":
        if isinstance(value, int):
            return cls(value)
        key = str(value).strip().upper().replace("-", "_")
        aliases = {"ADMIN": "SYSTEM_ADMIN", "SYSADMIN": "SYSTEM_ADMIN"}
        key = aliases.get(key, key)
        try:
            return cls[key]
        except KeyError as exc:
            raise ValueError(f"unknown role: {value!r}") from exc


@dataclass(frozen=True)
class ApiPrincipal:
    """An authenticated caller. ``name`` never contains the raw token.

    ``tenant_id`` scopes the principal to one tenant; ``None`` means the caller
    is part of the single-tenant compatibility mode (no cross-tenant checks)."""

    name: str
    role: Role
    tenant_id: str | None = None


def _principal_name(token: str, role: Role) -> str:
    # Non-reversible label so logs can identify a key without leaking it.
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()[:8]
    return f"{role.name.lower()}:{digest}"


@dataclass
class ControlPlaneConfig:
    api_keys: dict[str, ApiPrincipal] = field(default_factory=dict)
    signing_keys: dict[str, str] = field(default_factory=dict)  # HMAC (symmetric)
    signing_public_keys: dict[str, str] = field(default_factory=dict)  # Ed25519 (hex)
    require_signature: bool = True
    auth_enabled: bool = True
    max_audit_records: int = 1000
    max_decisions_cached: int = 500
    db_path: str | None = None  # SQLite file; None = in-memory (no durability)
    db_url: str | None = None  # Postgres DSN; takes precedence over db_path
    encryption_key: str | None = None  # Fernet key; None = plaintext at rest

    @property
    def is_single_tenant_compat(self) -> bool:
        """True when no principal declares a tenant — the legacy single-tenant
        mode where cross-tenant checks are bypassed. Production must reject it."""
        return not any(p.tenant_id for p in self.api_keys.values())

    def build_repository(self):
        """A durable repository if a DB is configured, else None (in-memory).

        ``AEGIS_DB_URL`` (Postgres) wins over ``AEGIS_DB_PATH`` (SQLite). When
        ``AEGIS_ENCRYPTION_KEY`` is set, sensitive columns are encrypted at rest.
        """
        from .crypto import build_encryptor

        encryptor = build_encryptor(self.encryption_key)
        if self.db_url:
            from .postgres import PostgresRepository

            return PostgresRepository(self.db_url, encryptor=encryptor)
        if self.db_path:
            from .persistence import SqliteRepository

            return SqliteRepository(self.db_path, encryptor=encryptor)
        return None

    def build_verifier(self) -> SignatureVerifier:
        # Prefer asymmetric Ed25519 (the control plane holds the private key;
        # this process only ever sees public keys).
        if self.signing_public_keys:
            return Ed25519SignatureVerifier(self.signing_public_keys)
        if self.signing_keys:
            return HmacSignatureVerifier(self.signing_keys)
        # No keys configured: reject every signature (fail closed). If
        # require_signature is also on, no active action can be authorized.
        return RejectAllVerifier()

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "ControlPlaneConfig":
        env = os.environ if env is None else env

        api_keys: dict[str, ApiPrincipal] = {}
        raw_keys = env.get("AEGIS_API_KEYS")
        if raw_keys:
            for token, spec in json.loads(raw_keys).items():
                if isinstance(spec, str):
                    role = Role.parse(spec)
                    name = _principal_name(token, role)
                    tenant = None
                else:
                    role = Role.parse(spec.get("role", "agent"))
                    name = spec.get("name") or _principal_name(token, role)
                    tenant = spec.get("tenant") or spec.get("tenant_id")
                api_keys[token] = ApiPrincipal(name=name, role=role, tenant_id=tenant)

        signing_keys: dict[str, str] = {}
        raw_signing = env.get("AEGIS_SIGNING_KEYS")
        if raw_signing:
            signing_keys = dict(json.loads(raw_signing))

        signing_public_keys: dict[str, str] = {}
        raw_ed = env.get("AEGIS_ED25519_PUBLIC_KEYS")
        if raw_ed:
            signing_public_keys = dict(json.loads(raw_ed))

        require_signature = _flag(env.get("AEGIS_REQUIRE_SIGNATURE"), default=True)
        auth_enabled = not _flag(env.get("AEGIS_AUTH_DISABLED"), default=False)

        return cls(
            api_keys=api_keys,
            signing_keys=signing_keys,
            signing_public_keys=signing_public_keys,
            require_signature=require_signature,
            auth_enabled=auth_enabled,
            db_path=env.get("AEGIS_DB_PATH") or None,
            db_url=env.get("AEGIS_DB_URL") or None,
            encryption_key=env.get("AEGIS_ENCRYPTION_KEY") or None,
        )


def _flag(value: str | None, *, default: bool) -> bool:
    if value is None:
        return default
    v = value.strip().lower()
    if v in TRUE_VALUES:
        return True
    if v in FALSE_VALUES:
        return False
    raise ValueError(f"invalid boolean flag: {value!r}")
