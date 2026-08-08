"""Authentication and role-based authorization for the control plane.

Callers present a bearer token. Tokens map to an :class:`ApiPrincipal` with a
:class:`Role`; higher roles subsume lower ones (an operator may call any
agent-level endpoint). Token comparison is constant-time. When auth is disabled
(local dev only, via ``AEGIS_AUTH_DISABLED``) every caller is treated as a
synthetic operator — never enable that in a shared environment.
"""

from __future__ import annotations

import hmac

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import ApiPrincipal, Role

_bearer = HTTPBearer(auto_error=False, description="Control-plane API key")

_DEV_PRINCIPAL = ApiPrincipal(name="dev-insecure", role=Role.OPERATOR)


def _authenticate(request: Request, credentials: HTTPAuthorizationCredentials | None) -> ApiPrincipal:
    config = request.app.state.config
    if not config.auth_enabled:
        return _DEV_PRINCIPAL

    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    for known_token, principal in config.api_keys.items():
        if hmac.compare_digest(known_token, token):
            return principal

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid api key",
        headers={"WWW-Authenticate": "Bearer"},
    )


def authenticate_authorization_header(request: Request, value: str | None) -> ApiPrincipal:
    """Authenticate a raw HTTP ``Authorization`` header outside dependency injection.

    Middleware uses this to protect state-changing operator UI routes with exactly the
    same token comparison and dev-mode semantics as the normal FastAPI dependencies.
    """
    raw = str(value or "").strip()
    credentials = None
    if raw:
        scheme, sep, token = raw.partition(" ")
        if sep and scheme.casefold() == "bearer" and token.strip():
            credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token.strip())
    return _authenticate(request, credentials)


def authenticated(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> ApiPrincipal:
    """Any valid principal, regardless of role (used for tenant checks)."""
    return _authenticate(request, credentials)


# Operational roles that sit outside the agent/operator scan ladder.
_NON_SCAN_ROLES = {Role.SYSTEM_ADMIN, Role.WORKER}


def require_role(minimum: Role):
    """Dependency factory: require at least ``minimum`` scan role.

    SYSTEM_ADMIN and WORKER are operational roles outside the agent/operator
    ladder and are explicitly rejected here — they cannot manage engagements or
    scans (a WORKER only executes tasks, via ``require_worker``)."""

    def dependency(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    ) -> ApiPrincipal:
        principal = _authenticate(request, credentials)
        if principal.role in _NON_SCAN_ROLES:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"{principal.role.name.lower()} role cannot manage scans/engagements",
            )
        if principal.role < minimum:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"requires role >= {minimum.name.lower()}",
            )
        return principal

    return dependency


def require_worker(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> ApiPrincipal:
    """The execution identity: only a WORKER may lease/run/heartbeat tasks."""
    principal = _authenticate(request, credentials)
    if principal.role != Role.WORKER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="requires the worker role",
        )
    return principal


require_agent = require_role(Role.AGENT)
require_operator = require_role(Role.OPERATOR)
