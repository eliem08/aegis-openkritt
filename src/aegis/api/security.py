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


def authenticated(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> ApiPrincipal:
    """Any valid principal, regardless of role (used for tenant checks)."""
    return _authenticate(request, credentials)


def require_role(minimum: Role):
    """Dependency factory: require at least ``minimum`` scan role.

    SYSTEM_ADMIN is an operational role and is explicitly rejected here — it
    cannot execute scans/engagements."""

    def dependency(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    ) -> ApiPrincipal:
        principal = _authenticate(request, credentials)
        if principal.role == Role.SYSTEM_ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="system-admin role cannot execute scans/engagements",
            )
        if principal.role < minimum:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"requires role >= {minimum.name.lower()}",
            )
        return principal

    return dependency


require_agent = require_role(Role.AGENT)
require_operator = require_role(Role.OPERATOR)
