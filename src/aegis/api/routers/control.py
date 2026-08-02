"""Kill switch control (§8, §13)."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ..config import ApiPrincipal
from ..dependencies import get_engagement
from ..schemas import KillIn, KillOut
from ..security import require_agent, require_operator
from ..store import Engagement

router = APIRouter(prefix="/engagements/{engagement_id}/kill", tags=["kill-switch"])


def _kill_out(engagement: Engagement) -> KillOut:
    st = engagement.engine.kill_switch.state
    return KillOut(active=st.fired, reason=st.reason, fired_at=st.fired_at, source=st.source)


@router.get(
    "",
    response_model=KillOut,
    dependencies=[Depends(require_agent)],
    summary="Kill-switch status",
)
def kill_status(engagement: Engagement = Depends(get_engagement)) -> KillOut:
    return _kill_out(engagement)


@router.post("", response_model=KillOut, summary="Fire the kill switch")
def fire_kill(
    body: KillIn,
    engagement: Engagement = Depends(get_engagement),
    principal: ApiPrincipal = Depends(require_operator),
) -> KillOut:
    engagement.engine.kill_switch.fire(body.reason, source=principal.name)
    return _kill_out(engagement)


@router.post("/reset", response_model=KillOut, summary="Reset the kill switch")
def reset_kill(
    engagement: Engagement = Depends(get_engagement),
    principal: ApiPrincipal = Depends(require_operator),
) -> KillOut:
    engagement.engine.kill_switch.reset(source=principal.name)
    return _kill_out(engagement)
