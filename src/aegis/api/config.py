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

from aegis.policy import HmacSignatureVerifier, RejectAllVerifier, SignatureVerifier

TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off", ""}


class Role(IntEnum):
    """Ordered roles. Higher value grants a superset of lower privileges."""

    AGENT = 1
    OPERATOR = 2

    @classmethod
    def parse(cls, value: str | int) -> "Role":
        if isinstance(value, int):
            return cls(value)
        key = str(value).strip().upper()
        try:
            return cls[key]
        except KeyError as exc:
            raise ValueError(f"unknown role: {value!r}") from exc


@dataclass(frozen=True)
class ApiPrincipal:
    """An authenticated caller. ``name`` never contains the raw token."""

    name: str
    role: Role


def _principal_name(token: str, role: Role) -> str:
    # Non-reversible label so logs can identify a key without leaking it.
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()[:8]
    return f"{role.name.lower()}:{digest}"


@dataclass
class ControlPlaneConfig:
    api_keys: dict[str, ApiPrincipal] = field(default_factory=dict)
    signing_keys: dict[str, str] = field(default_factory=dict)
    require_signature: bool = True
    auth_enabled: bool = True
    max_audit_records: int = 1000
    max_decisions_cached: int = 500
    db_path: str | None = None  # SQLite file; None = in-memory (no durability)

    def build_repository(self):
        """A durable repository if a DB is configured, else None (in-memory)."""
        if not self.db_path:
            return None
        from .persistence import SqliteRepository

        return SqliteRepository(self.db_path)

    def build_verifier(self) -> SignatureVerifier:
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
                else:
                    role = Role.parse(spec.get("role", "agent"))
                    name = spec.get("name") or _principal_name(token, role)
                api_keys[token] = ApiPrincipal(name=name, role=role)

        signing_keys: dict[str, str] = {}
        raw_signing = env.get("AEGIS_SIGNING_KEYS")
        if raw_signing:
            signing_keys = dict(json.loads(raw_signing))

        require_signature = _flag(env.get("AEGIS_REQUIRE_SIGNATURE"), default=True)
        auth_enabled = not _flag(env.get("AEGIS_AUTH_DISABLED"), default=False)

        return cls(
            api_keys=api_keys,
            signing_keys=signing_keys,
            require_signature=require_signature,
            auth_enabled=auth_enabled,
            db_path=env.get("AEGIS_DB_PATH") or None,
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
