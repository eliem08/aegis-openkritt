"""Read the per-engagement audit trail (operator only, §12)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from ..dependencies import get_engagement
from ..security import require_operator
from ..store import Engagement

router = APIRouter(prefix="/engagements/{engagement_id}/audit", tags=["audit"])


@router.get(
    "",
    dependencies=[Depends(require_operator)],
    summary="Recent policy-decision records for this engagement",
)
def get_audit(
    engagement: Engagement = Depends(get_engagement),
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict:
    records = engagement.audit.recent(limit)
    return {"engagement_id": engagement.id, "count": len(records), "records": records}
