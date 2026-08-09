"""Short-lived HMAC authorizations for the egress boundary."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import asdict, dataclass, field
from urllib.parse import urlsplit

from aegis.gateway import NetworkProfile

MAX_TOKEN_LIFETIME = 300


class EgressTokenError(ValueError):
    pass


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise EgressTokenError("malformed token encoding") from exc


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class EgressClaims:
    tenant_id: str
    engagement_id: str
    profile: str
    method: str
    destination: str
    expires_at: int
    issued_at: int
    budget_id: str
    request_limit: int
    scope: list[str] = field(default_factory=list)
    allowed_providers: list[str] = field(default_factory=list)
    oast_host: str | None = None
    allowed_methods: list[str] = field(default_factory=list)

    def validate(self, *, now: int | None = None) -> None:
        current = int(time.time()) if now is None else now
        if not self.tenant_id or not self.engagement_id or not self.budget_id:
            raise EgressTokenError("token identity fields are required")
        try:
            NetworkProfile(self.profile)
        except ValueError as exc:
            raise EgressTokenError("unknown network profile") from exc
        method = self.method.upper()
        if method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
            raise EgressTokenError("unsupported HTTP method")
        parts = urlsplit(self.destination)
        if parts.scheme not in {"http", "https", "ws", "wss"} or not parts.hostname or parts.username:
            raise EgressTokenError("destination must be an HTTP(S) or WebSocket URL without userinfo")
        if parts.scheme in {"ws", "wss"} and method != "GET":
            raise EgressTokenError("WebSocket destinations require a GET handshake")
        if self.expires_at <= current:
            raise EgressTokenError("token expired")
        if self.issued_at > current + 5:
            raise EgressTokenError("token issued in the future")
        if self.expires_at - self.issued_at > MAX_TOKEN_LIFETIME:
            raise EgressTokenError("token lifetime exceeds the maximum")
        if self.request_limit <= 0:
            raise EgressTokenError("request limit must be positive")
        if self.profile.startswith("target-") and not self.scope:
            raise EgressTokenError("target profiles require scope")
        if self.profile == NetworkProfile.PASSIVE_PROVIDER.value and not self.allowed_providers:
            raise EgressTokenError("passive-provider profile requires providers")
        if self.profile == NetworkProfile.PRIVATE_OAST.value and not self.oast_host:
            raise EgressTokenError("private-oast profile requires an OAST host")


def issue_token(claims: EgressClaims, secret: str | bytes, *, now: int | None = None) -> str:
    claims.validate(now=now)
    payload = _canonical(asdict(claims))
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    signature = hmac.new(key, payload, hashlib.sha256).digest()
    return f"{_b64encode(payload)}.{_b64encode(signature)}"


def verify_token(token: str, secret: str | bytes, *, now: int | None = None) -> EgressClaims:
    try:
        payload_part, signature_part = token.split(".", 1)
    except ValueError as exc:
        raise EgressTokenError("malformed token") from exc
    payload = _b64decode(payload_part)
    signature = _b64decode(signature_part)
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    expected = hmac.new(key, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, signature):
        raise EgressTokenError("invalid token signature")
    try:
        document = json.loads(payload)
        claims = EgressClaims(**document)
    except (json.JSONDecodeError, TypeError) as exc:
        raise EgressTokenError("invalid token claims") from exc
    claims.validate(now=now)
    return claims
