"""Liveness and readiness probes (unauthenticated)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Response, status

from ..config import ControlPlaneConfig
from ..dependencies import get_config

router = APIRouter(tags=["system"])


@router.get("/healthz", summary="Liveness probe")
def healthz() -> dict:
    return {"status": "ok"}


@router.get("/readyz", summary="Readiness probe")
def readyz(response: Response, config: ControlPlaneConfig = Depends(get_config)) -> dict:
    checks = {
        "signing_keys_configured": bool(config.signing_keys)
        or bool(config.signing_public_keys)
        or not config.require_signature,
        "auth_configured": bool(config.api_keys) or not config.auth_enabled,
    }
    ready = all(checks.values())
    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"ready": ready, "checks": checks}
