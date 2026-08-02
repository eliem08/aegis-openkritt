"""Request policy decisions and commit budget for actions that ran.

Two-phase by design: ``POST /decisions`` evaluates without spending any budget;
``POST /decisions/{request_id}/commit`` debits rate/spend only after the agent
has actually executed an allowed action.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status

from aegis.policy import ActionRequest

from ..dependencies import get_active_engagement, get_engagement
from ..schemas import CommitOut, DecisionIn, DecisionOut
from ..security import require_agent
from ..store import Engagement, StoredDecision

router = APIRouter(prefix="/engagements/{engagement_id}/decisions", tags=["decisions"])


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@router.post(
    "",
    response_model=DecisionOut,
    dependencies=[Depends(require_agent)],
    summary="Evaluate a proposed action against policy (non-mutating)",
)
def request_decision(
    body: DecisionIn,
    engagement: Engagement = Depends(get_active_engagement),
) -> DecisionOut:
    now = _utcnow()
    tokens = engagement.approvals.tokens_for(body.action, body.target, now)

    kwargs = dict(
        target=body.target,
        action=body.action,
        tier_hint=body.tier_hint,
        description=body.description,
        identity=body.identity,
        estimated_cost=body.estimated_cost,
        touches_production=body.touches_production,
        approvals=frozenset(tokens),
    )
    if body.request_id:
        kwargs["request_id"] = body.request_id
    action_request = ActionRequest(**kwargs)

    decision = engagement.engine.authorize(action_request, now=now)
    engagement.remember_decision(StoredDecision(decision=decision, request=action_request))
    if decision.allowed:
        engagement.approvals.consume_single_use(body.action, body.target, now)

    return DecisionOut(**decision.as_dict())


@router.post(
    "/{request_id}/commit",
    response_model=CommitOut,
    dependencies=[Depends(require_agent)],
    summary="Debit budget for an allowed decision that was executed",
)
def commit_decision(
    request_id: str,
    engagement: Engagement = Depends(get_engagement),
) -> CommitOut:
    stored = engagement.get_decision(request_id)
    if stored is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="decision not found")
    if not stored.decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"cannot commit a {stored.decision.verdict.value} decision",
        )
    if stored.committed:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="already committed")

    engagement.engine.commit(stored.decision, request=stored.request, now=_utcnow())
    stored.committed = True
    return CommitOut(
        request_id=request_id, committed=True, verdict=stored.decision.verdict.value
    )
