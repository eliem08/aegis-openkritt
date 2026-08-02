"""Shared FastAPI dependencies.

Application state (config, verifier, store) lives on ``app.state`` so
``create_app`` can build fully isolated app instances for tests.
"""

from __future__ import annotations

from fastapi import Depends, HTTPException, Path, Request, status

from .config import ControlPlaneConfig
from .store import Engagement, EngagementStore


def get_config(request: Request) -> ControlPlaneConfig:
    return request.app.state.config


def get_store(request: Request) -> EngagementStore:
    return request.app.state.store


def get_engagement(
    engagement_id: str = Path(..., description="The authorization_id of the engagement"),
    store: EngagementStore = Depends(get_store),
) -> Engagement:
    engagement = store.get(engagement_id)
    if engagement is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement not found")
    return engagement


def get_active_engagement(engagement: Engagement = Depends(get_engagement)) -> Engagement:
    if not engagement.is_active:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="engagement is closed",
        )
    return engagement
