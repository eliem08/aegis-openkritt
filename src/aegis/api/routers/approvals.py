"""Operator approval grants (§5 human-in-the-loop)."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status

from aegis.policy import ActionRequest

from ..config import ApiPrincipal
from ..dependencies import get_engagement
from ..schemas import ApprovalIn, ApprovalOut
from ..security import require_operator
from ..store import Engagement

router = APIRouter(prefix="/engagements/{engagement_id}/approvals", tags=["approvals"])


def _utcnow() -> datetime:
    return datetime.now(UTC)


@router.post(
    "",
    response_model=ApprovalOut,
    status_code=status.HTTP_201_CREATED,
    summary="Grant approval tokens for an action on a target",
)
def create_approval(
    body: ApprovalIn,
    engagement: Engagement = Depends(get_engagement),
    principal: ApiPrincipal = Depends(require_operator),
) -> ApprovalOut:
    tokens = body.tokens
    if tokens is None:
        # Compute exactly which tokens this action would require (dry-run, not
        # audited) so the operator can approve without copying tokens by hand.
        dry = ActionRequest(target=body.target, action=body.action)
        decision = engagement.engine.authorize(dry, now=_utcnow(), record=False)
        tokens = decision.required_approvals
        if not tokens:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "action requires no approval "
                    f"(verdict={decision.verdict.value}); nothing to grant"
                ),
            )

    grant = engagement.approvals.grant(
        action=body.action,
        target=body.target,
        tokens=tokens,
        granted_by=principal.name,
        expires_at=body.expires_at,
        single_use=body.single_use,
    )
    return ApprovalOut.from_grant(grant)


@router.get(
    "",
    response_model=list[ApprovalOut],
    dependencies=[Depends(require_operator)],
    summary="List approval grants",
)
def list_approvals(engagement: Engagement = Depends(get_engagement)) -> list[ApprovalOut]:
    return [ApprovalOut.from_grant(g) for g in engagement.approvals.list()]


@router.delete(
    "/{grant_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_operator)],
    summary="Revoke an approval grant",
)
def revoke_approval(grant_id: str, engagement: Engagement = Depends(get_engagement)) -> None:
    if not engagement.approvals.revoke(grant_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="grant not found or already revoked"
        )
