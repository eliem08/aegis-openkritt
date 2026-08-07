"""Advanced control-plane primitives for profitable, evidence-led security research.

These contracts do not execute live actions. They make agent proposals, authenticated
session plans, skill methodologies, model routing, commit-change triage, and stateful API
sequences explicit so the existing policy engine can approve or reject them.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ActionRisk(str, Enum):
    PASSIVE = "passive"
    READ_ONLY = "read_only"
    CONTROLLED_STATE_CHANGE = "controlled_state_change"


class AgentActionProposal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    proposal_id: str
    agent: str
    action: str
    reason: str
    scope_id: str
    asset_key: str
    risk: ActionRisk
    estimated_requests: int = Field(ge=0, le=100)
    estimated_cost: Decimal = Field(default=Decimal(0), ge=0)
    expected_information_gain: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_refs: tuple[str, ...] = ()
    requires_network: bool = False
    human_approval_ref: str | None = None

    @field_validator("proposal_id", "agent", "action", "reason", "scope_id", "asset_key")
    @classmethod
    def nonempty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("proposal identity fields are required")
        return value

    @model_validator(mode="after")
    def approval_for_state_change(self) -> "AgentActionProposal":
        if self.risk == ActionRisk.CONTROLLED_STATE_CHANGE and not self.human_approval_ref:
            raise ValueError("controlled state changes require a human approval reference")
        return self


@dataclass(frozen=True)
class ProposalDecision:
    allowed: bool
    reason: str
    reserved_cost: Decimal = Decimal(0)
    reserved_requests: int = 0


class ProposalGate:
    """Deterministic per-scope request and cost gate for agent proposals."""
    def __init__(self, *, scope_id: str, remaining_budget: Decimal,
                 request_cap: int, allow_network: bool = False):
        if remaining_budget < 0 or request_cap < 0:
            raise ValueError("budget and request cap cannot be negative")
        self.scope_id = scope_id
        self.remaining_budget = remaining_budget
        self.remaining_requests = request_cap
        self.allow_network = allow_network

    def evaluate(self, proposal: AgentActionProposal) -> ProposalDecision:
        if proposal.scope_id != self.scope_id:
            return ProposalDecision(False, "scope_mismatch")
        if proposal.requires_network and not self.allow_network:
            return ProposalDecision(False, "network_not_authorized")
        if proposal.estimated_requests > self.remaining_requests:
            return ProposalDecision(False, "request_budget_exceeded")
        if proposal.estimated_cost > self.remaining_budget:
            return ProposalDecision(False, "cost_budget_exceeded")
        self.remaining_requests -= proposal.estimated_requests
        self.remaining_budget -= proposal.estimated_cost
        return ProposalDecision(True, "approved", proposal.estimated_cost,
                                proposal.estimated_requests)


class SessionRole(str, Enum):
    ANONYMOUS = "anonymous"
    USER_A = "user_a"
    USER_B = "user_b"
    ADMIN = "admin"
    TENANT_A = "tenant_a"
    TENANT_B = "tenant_b"


class BrowserAction(str, Enum):
    NAVIGATE = "navigate"
    LOGIN = "login"
    DISCOVER = "discover"
    CAPTURE_TRAFFIC = "capture_traffic"
    SUBMIT_FORM = "submit_form"
    MUTATE_STATE = "mutate_state"


class AuthenticatedSessionPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    base_url: str
    roles: tuple[SessionRole, ...]
    actions: tuple[BrowserAction, ...]
    maximum_requests: int = Field(ge=1, le=500)
    capture_har: bool = True
    capture_trace: bool = True
    human_approval_ref: str | None = None

    @model_validator(mode="after")
    def state_change_requires_approval(self) -> "AuthenticatedSessionPlan":
        if BrowserAction.MUTATE_STATE in self.actions and not self.human_approval_ref:
            raise ValueError("browser state mutation requires human approval")
        if len(set(self.roles)) != len(self.roles):
            raise ValueError("session roles must be unique")
        return self


class SkillMethodology(BaseModel):
    """Declarative result of parsing an untrusted third-party skill document."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    skill_id: str
    languages: tuple[str, ...] = ()
    weaknesses: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    sinks: tuple[str, ...] = ()
    questions: tuple[str, ...] = ()
    content_digest: str

    @classmethod
    def from_untrusted_json(cls, skill_id: str, raw: str) -> "SkillMethodology":
        """Accept only JSON data fields; raw imperative text never reaches an agent."""
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("skill methodology must be strict JSON") from exc
        if not isinstance(parsed, dict):
            raise ValueError("skill methodology must be a JSON object")
        allowed = {"languages", "weaknesses", "sources", "sinks", "questions"}
        unknown = set(parsed) - allowed
        if unknown:
            raise ValueError(f"unsupported skill fields: {sorted(unknown)}")
        normalized = {}
        for key in allowed:
            value = parsed.get(key, ())
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ValueError(f"{key} must be a list of strings")
            normalized[key] = tuple(dict.fromkeys(item.strip() for item in value if item.strip()))
        digest = "skill1:" + hashlib.sha256(raw.encode()).hexdigest()
        return cls(skill_id=skill_id, content_digest=digest, **normalized)


class ChangeSignal(str, Enum):
    AUTHORIZATION = "authorization"
    AUTHENTICATION = "authentication"
    FILE_UPLOAD = "file_upload"
    DESERIALIZATION = "deserialization"
    API_ROUTE = "api_route"
    INFRA_EXPOSURE = "infra_exposure"
    SECRET_PERMISSION = "secret_permission"
    DEPENDENCY_SECURITY = "dependency_security"


@dataclass(frozen=True)
class ChangeAssessment:
    path: str
    signals: tuple[ChangeSignal, ...]
    priority: float
    reasons: tuple[str, ...]


def assess_changed_path(path: str, added_text: str = "") -> ChangeAssessment:
    lower = path.lower().replace("\\", "/")
    text = added_text.lower()
    signals: list[ChangeSignal] = []
    reasons: list[str] = []

    def mark(signal: ChangeSignal, reason: str):
        if signal not in signals:
            signals.append(signal)
            reasons.append(reason)

    if any(token in lower for token in ("authz", "permission", "policy", "access_control")) or any(token in text for token in ("authorize(", "permission", "is_admin", "tenant_id")):
        mark(ChangeSignal.AUTHORIZATION, "authorization-sensitive code changed")
    if any(token in lower for token in ("login", "oauth", "session", "jwt", "auth/")):
        mark(ChangeSignal.AUTHENTICATION, "authentication/session code changed")
    if any(token in lower for token in ("upload", "attachment", "multipart")):
        mark(ChangeSignal.FILE_UPLOAD, "file upload surface changed")
    if any(token in text for token in ("pickle.loads", "yaml.load(", "objectinputstream", "unserialize(")):
        mark(ChangeSignal.DESERIALIZATION, "dangerous deserialization primitive added")
    if any(token in lower for token in ("routes", "router", "controller", "openapi", "swagger")):
        mark(ChangeSignal.API_ROUTE, "API route or schema changed")
    if lower.endswith((".tf", ".yaml", ".yml")) and any(token in text for token in ("0.0.0.0/0", "public-read", "allusers", "ingress", "security_group")):
        mark(ChangeSignal.INFRA_EXPOSURE, "infrastructure exposure changed")
    if any(token in lower for token in ("workflow", ".github/actions", "iam", "permissions")) and any(token in text for token in ("write-all", "id-token: write", "secrets", "contents: write")):
        mark(ChangeSignal.SECRET_PERMISSION, "CI or IAM permissions expanded")
    if lower.endswith(("requirements.txt", "poetry.lock", "package-lock.json", "yarn.lock", "go.sum", "cargo.lock")):
        mark(ChangeSignal.DEPENDENCY_SECURITY, "dependency lockfile changed")
    weights = {
        ChangeSignal.AUTHORIZATION: .30, ChangeSignal.AUTHENTICATION: .25,
        ChangeSignal.FILE_UPLOAD: .22, ChangeSignal.DESERIALIZATION: .35,
        ChangeSignal.API_ROUTE: .12, ChangeSignal.INFRA_EXPOSURE: .30,
        ChangeSignal.SECRET_PERMISSION: .28, ChangeSignal.DEPENDENCY_SECURITY: .08,
    }
    priority = min(1.0, sum(weights[s] for s in signals))
    return ChangeAssessment(path, tuple(signals), priority, tuple(reasons))


class ModelTier(str, Enum):
    LOCAL = "local"
    STANDARD = "standard"
    STRONG = "strong"
    VERIFIER = "verifier"


@dataclass(frozen=True)
class ModelRoute:
    tier: ModelTier
    reason: str
    maximum_cost: Decimal
    independent_verifier_required: bool


class ModelRouter:
    def route(self, *, complexity: float, files: int, evidence_verification: bool,
              remaining_budget: Decimal) -> ModelRoute:
        if not 0 <= complexity <= 1 or files < 0 or remaining_budget < 0:
            raise ValueError("invalid routing inputs")
        if evidence_verification:
            return ModelRoute(ModelTier.VERIFIER, "independent evidence challenge",
                              min(remaining_budget, Decimal("2.00")), False)
        if complexity >= .75 or files >= 20:
            tier, cap, reason = ModelTier.STRONG, Decimal("5.00"), "cross-file/complex reasoning"
        elif complexity >= .35 or files >= 5:
            tier, cap, reason = ModelTier.STANDARD, Decimal("1.00"), "moderate source reasoning"
        else:
            tier, cap, reason = ModelTier.LOCAL, Decimal("0.10"), "classification and parsing"
        if remaining_budget < cap:
            tier, cap, reason = ModelTier.LOCAL, remaining_budget, "budget-constrained fallback"
        return ModelRoute(tier, reason, min(cap, remaining_budget), tier == ModelTier.STRONG)


class ApiOperation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operation_id: str
    method: str
    path: str
    produces: tuple[str, ...] = ()
    consumes: tuple[str, ...] = ()
    state_changing: bool = False


class StatefulApiPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operations: tuple[ApiOperation, ...]
    maximum_sequences: int = Field(default=20, ge=1, le=500)
    human_approval_ref: str | None = None

    @model_validator(mode="after")
    def approval_for_mutation(self) -> "StatefulApiPlan":
        if any(op.state_changing for op in self.operations) and not self.human_approval_ref:
            raise ValueError("state-changing API sequences require human approval")
        ids = [op.operation_id for op in self.operations]
        if len(ids) != len(set(ids)):
            raise ValueError("operation IDs must be unique")
        return self

    def dependency_order(self) -> list[str]:
        """Topologically order operations by produced/consumed resource names."""
        remaining = list(self.operations)
        produced: set[str] = set()
        ordered: list[str] = []
        while remaining:
            ready = [op for op in remaining if set(op.consumes) <= produced]
            if not ready:
                unresolved = {op.operation_id: sorted(set(op.consumes) - produced) for op in remaining}
                raise ValueError(f"unresolved API dependencies: {unresolved}")
            ready.sort(key=lambda op: op.operation_id)
            for op in ready:
                ordered.append(op.operation_id)
                produced.update(op.produces)
                remaining.remove(op)
        return ordered
