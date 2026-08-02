"""Engagement lifecycle: register an authorization, list, inspect, close."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from aegis.policy import Authorization

from ..config import ApiPrincipal, ControlPlaneConfig
from ..dependencies import get_config, get_engagement, get_store
from ..schemas import EngagementOut
from ..security import require_agent, require_operator
from ..store import DuplicateEngagementError, Engagement, EngagementStore, registration_reasons

router = APIRouter(prefix="/engagements", tags=["engagements"])


@router.post(
    "",
    response_model=EngagementOut,
    status_code=status.HTTP_201_CREATED,
    summary="Register a signed authorization and open an engagement",
)
def create_engagement(
    authorization: Authorization,
    request: Request,
    store: EngagementStore = Depends(get_store),
    config: ControlPlaneConfig = Depends(get_config),
    principal: ApiPrincipal = Depends(require_operator),
) -> EngagementOut:
    # An operator may only register engagements for its own tenant. The tenant
    # is the authorization's customer_id.
    if not config.is_single_tenant_compat and principal.tenant_id != authorization.customer_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="cannot register an engagement for another tenant",
        )
    verifier = request.app.state.verifier
    reasons = registration_reasons(authorization, verifier, config.require_signature)
    if reasons:
        raise HTTPException(
            status_code=422,  # Unprocessable Content
            detail={
                "error": "authorization_rejected",
                "reasons": [r.as_dict() for r in reasons],
            },
        )
    try:
        engagement = store.create(authorization)
    except DuplicateEngagementError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"engagement {authorization.authorization_id!r} already exists",
        )
    return EngagementOut.from_engagement(engagement)


@router.get(
    "",
    response_model=list[EngagementOut],
    summary="List engagements (only the caller's tenant)",
)
def list_engagements(
    store: EngagementStore = Depends(get_store),
    config: ControlPlaneConfig = Depends(get_config),
    principal: ApiPrincipal = Depends(require_agent),
) -> list[EngagementOut]:
    items = store.list()
    if not config.is_single_tenant_compat:
        items = [e for e in items if e.tenant_id == principal.tenant_id]
    return [EngagementOut.from_engagement(e) for e in items]


@router.get(
    "/{engagement_id}",
    response_model=EngagementOut,
    dependencies=[Depends(require_agent)],
    summary="Get one engagement",
)
def get_one(engagement: Engagement = Depends(get_engagement)) -> EngagementOut:
    return EngagementOut.from_engagement(engagement)


@router.delete(
    "/{engagement_id}",
    response_model=EngagementOut,
    dependencies=[Depends(require_operator)],
    summary="Close an engagement (soft)",
)
def close_engagement(engagement: Engagement = Depends(get_engagement)) -> EngagementOut:
    engagement.close()
    return EngagementOut.from_engagement(engagement)
