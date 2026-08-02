"""Pydantic request/response models for the control-plane API.

These shape the OpenAPI contract. Request bodies use ``extra="forbid"`` so a
typo or an unexpected field is a 422, not a silently ignored value.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from aegis.policy import ConsequenceTier

from .store import ApprovalGrant, Engagement


# --- engagements ----------------------------------------------------------

class EngagementOut(BaseModel):
    id: str
    customer_id: str
    environment: str
    status: str
    created_at: datetime
    targets: list[str]
    valid_from: datetime
    valid_until: datetime
    permitted_actions: list[str]
    prohibited_actions: list[str]
    approval_required_for: list[str]

    @classmethod
    def from_engagement(cls, e: Engagement) -> "EngagementOut":
        a = e.authorization
        return cls(
            id=e.id,
            customer_id=a.customer_id,
            environment=a.environment.value,
            status=e.status,
            created_at=e.created_at,
            targets=list(a.targets),
            valid_from=a.valid_from,
            valid_until=a.valid_until,
            permitted_actions=list(a.permitted_actions),
            prohibited_actions=list(a.prohibited_actions),
            approval_required_for=list(a.approval_required_for),
        )


# --- decisions ------------------------------------------------------------

class DecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str
    action: str
    tier_hint: ConsequenceTier | None = None
    description: str = ""
    identity: str | None = None
    estimated_cost: float = Field(default=0.0, ge=0)
    touches_production: bool = False
    request_id: str | None = Field(
        default=None,
        description="Optional client-supplied id; reuse it to commit the decision later.",
    )


class ReasonOut(BaseModel):
    code: str
    message: str
    verdict: str


class DecisionOut(BaseModel):
    verdict: str
    tier: str | None
    reasons: list[ReasonOut]
    required_approvals: list[str]
    incidents: list[str]
    request_id: str | None
    authorization_id: str | None
    target: str | None
    action: str | None
    evaluated_at: str


class CommitOut(BaseModel):
    request_id: str
    committed: bool
    verdict: str


# --- approvals ------------------------------------------------------------

class ApprovalIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str
    target: str
    tokens: list[str] | None = Field(
        default=None,
        description="Tokens to grant. If omitted, the required tokens are computed for you.",
    )
    expires_at: datetime | None = None
    single_use: bool = False


class ApprovalOut(BaseModel):
    grant_id: str
    action: str
    target: str
    tokens: list[str]
    granted_by: str
    granted_at: datetime
    expires_at: datetime | None
    single_use: bool
    used: bool
    revoked: bool

    @classmethod
    def from_grant(cls, g: ApprovalGrant) -> "ApprovalOut":
        return cls(
            grant_id=g.grant_id,
            action=g.action,
            target=g.target,
            tokens=sorted(g.tokens),
            granted_by=g.granted_by,
            granted_at=g.granted_at,
            expires_at=g.expires_at,
            single_use=g.single_use,
            used=g.used,
            revoked=g.revoked,
        )


# --- kill switch ----------------------------------------------------------

class KillIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1)


class KillOut(BaseModel):
    active: bool
    reason: str | None
    fired_at: datetime | None
    source: str | None
