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


# --- scans ----------------------------------------------------------------

class StageIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1, description="Local handle used by tasks + dependencies")
    stage_type: str = Field(min_length=1)
    depends_on: list[str] = Field(default_factory=list, description="Other stage keys")


class TaskIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    adapter: str = Field(min_length=1, description="Registered adapter name")
    target: str = Field(min_length=1)
    stage: str = Field(min_length=1, description="Stage key this task belongs to")
    input_hash: str = ""
    est_spend: float = Field(default=0.0, ge=0)


class ScanCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    engagement_id: str = Field(min_length=1)
    stages: list[StageIn] = Field(min_length=1)
    tasks: list[TaskIn] = Field(min_length=1)


class ScanOut(BaseModel):
    scan_id: str
    tenant_id: str
    engagement_id: str
    status: str
    scope_digest: str
    manifest_set: list[str]
    created_at: datetime

    @classmethod
    def from_scan(cls, s) -> "ScanOut":
        return cls(
            scan_id=s.scan_id, tenant_id=s.tenant_id, engagement_id=s.engagement_id,
            status=s.status, scope_digest=s.scope_digest, manifest_set=list(s.manifest_set),
            created_at=s.created_at,
        )


class StageOut(BaseModel):
    stage_id: str
    stage_type: str
    depends_on: list[str]
    status: str

    @classmethod
    def from_stage(cls, s) -> "StageOut":
        return cls(stage_id=s.stage_id, stage_type=s.stage_type,
                   depends_on=list(s.depends_on), status=s.status)


class TaskOut(BaseModel):
    task_id: str
    stage_id: str
    target: str
    adapter: str
    adapter_version: str
    capability_tier: str
    status: str
    attempts: int
    max_attempts: int
    result_summary: dict | None

    @classmethod
    def from_task(cls, t) -> "TaskOut":
        return cls(
            task_id=t.task_id, stage_id=t.stage_id, target=t.target, adapter=t.adapter,
            adapter_version=t.adapter_version, capability_tier=t.capability_tier, status=t.status,
            attempts=t.attempts, max_attempts=t.max_attempts, result_summary=t.result_summary,
        )


class ArtifactOut(BaseModel):
    """Sanitized artifact metadata — never the raw payload or storage reference."""

    artifact_id: str
    task_id: str
    kind: str
    classification: str
    size: int
    created_at: datetime

    @classmethod
    def from_artifact(cls, a) -> "ArtifactOut":
        return cls(artifact_id=a.artifact_id, task_id=a.task_id, kind=a.kind,
                   classification=a.classification, size=a.size, created_at=a.created_at)


class ScanDetailOut(ScanOut):
    stages: list[StageOut]
    tasks: list[TaskOut]
    artifacts: list[ArtifactOut]


class StepOut(BaseModel):
    ran: bool
    task_id: str | None = None
    outcome: str | None = None
    events: int = 0
    reason: str = ""


class CancelOut(BaseModel):
    scan_id: str
    cancelled: int


class RecoverOut(BaseModel):
    scan_id: str
    reclaimed: list[str]


class HeartbeatOut(BaseModel):
    task_id: str
    extended: bool


class ArtifactReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(description="Must be 'quarantine_review' to release a raw reference")
    justification: str = Field(min_length=1)


class ArtifactRawOut(BaseModel):
    artifact_id: str
    classification: str
    storage_ref: str | None
    note: str
