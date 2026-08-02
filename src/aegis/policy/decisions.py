"""Decision, reason, and request types shared across the policy layer.

The policy engine's contract is: given an :class:`ActionRequest`, return a
single :class:`PolicyDecision`. The decision is fully auditable — it carries
every reason that contributed, any incidents to raise, and the tier that was
assigned — so a human or another agent can reconstruct exactly why an action
was allowed, queued for approval, denied, or escalated (§12).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from .consequence import ConsequenceTier


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Verdict(str, Enum):
    """The four possible outcomes, ordered by severity.

    * ``ALLOW`` — proceed.
    * ``REQUIRE_APPROVAL`` — safe to run *once* the named approval is granted;
      the action is queued, not rejected.
    * ``ESCALATE`` — stop and hand to a human: authorization is missing /
      ambiguous, or observed content tried to redirect the agent (§10).
    * ``DENY`` — hard stop. The action is prohibited or out of scope and must
      never run under any framing.
    """

    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    ESCALATE = "escalate"
    DENY = "deny"

    @property
    def severity(self) -> int:
        return _VERDICT_SEVERITY[self]

    @property
    def is_blocking(self) -> bool:
        return self is not Verdict.ALLOW


_VERDICT_SEVERITY: dict[Verdict, int] = {
    Verdict.ALLOW: 0,
    Verdict.REQUIRE_APPROVAL: 1,
    Verdict.ESCALATE: 2,
    Verdict.DENY: 3,
}


class ReasonCode(str, Enum):
    """Stable, machine-readable reason codes for audit and analytics."""

    OK = "ok"
    KILL_SWITCH_ACTIVE = "kill_switch_active"
    NO_AUTHORIZATION = "no_authorization"
    AUTHORIZATION_NOT_YET_VALID = "authorization_not_yet_valid"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    AUTHORIZATION_MALFORMED = "authorization_malformed"
    OWNERSHIP_PROOF_MISSING = "ownership_proof_missing"
    SIGNATURE_MISSING = "signature_missing"
    SIGNATURE_INVALID = "signature_invalid"
    TARGET_OUT_OF_SCOPE = "target_out_of_scope"
    ACTION_PROHIBITED = "action_prohibited"
    ACTION_NOT_PERMITTED = "action_not_permitted"
    APPROVAL_REQUIRED = "approval_required"
    RATE_BUDGET_EXCEEDED = "rate_budget_exceeded"
    SPEND_BUDGET_EXCEEDED = "spend_budget_exceeded"
    CONCURRENCY_EXCEEDED = "concurrency_exceeded"
    ENVIRONMENT_MISMATCH = "environment_mismatch"
    UNKNOWN_ACTION = "unknown_action"


# Incidents that a blocking reason should raise to the control plane (§13).
INCIDENT_FOR_REASON: dict[ReasonCode, str] = {
    ReasonCode.TARGET_OUT_OF_SCOPE: "SCOPE_ESCAPE",
    ReasonCode.ACTION_PROHIBITED: "PROHIBITED_ACTION_BLOCKED",
    ReasonCode.KILL_SWITCH_ACTIVE: "KILL_SWITCH",
    ReasonCode.SIGNATURE_INVALID: "AUTHORIZATION_TAMPERED",
}


@dataclass(frozen=True)
class Reason:
    """A single contributing factor to a decision."""

    code: ReasonCode
    message: str
    verdict: Verdict

    def as_dict(self) -> dict:
        return {"code": self.code.value, "message": self.message, "verdict": self.verdict.value}


@dataclass
class ActionRequest:
    """A proposed action the agent wants to take against a target.

    ``tier_hint`` lets a planner declare its own assessment; the classifier
    still applies and can only raise the tier, never lower it. ``approvals`` is
    the set of approval tokens already granted for this request (see
    :mod:`aegis.policy.engine` for how required tokens are derived).
    """

    target: str
    action: str
    tier_hint: ConsequenceTier | None = None
    description: str = ""
    identity: str | None = None
    estimated_cost: float = 0.0
    approvals: frozenset[str] = field(default_factory=frozenset)
    touches_production: bool = False
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex)


@dataclass
class PolicyDecision:
    """The engine's verdict on an :class:`ActionRequest`."""

    verdict: Verdict
    tier: ConsequenceTier | None
    reasons: list[Reason] = field(default_factory=list)
    required_approvals: list[str] = field(default_factory=list)
    incidents: list[str] = field(default_factory=list)
    request_id: str | None = None
    authorization_id: str | None = None
    target: str | None = None
    action: str | None = None
    evaluated_at: datetime = field(default_factory=_utcnow)

    @property
    def allowed(self) -> bool:
        return self.verdict == Verdict.ALLOW

    @property
    def primary_reason(self) -> Reason | None:
        if not self.reasons:
            return None
        return max(self.reasons, key=lambda r: r.verdict.severity)

    def as_dict(self) -> dict:
        """A JSON-serialisable audit record of the decision."""
        return {
            "verdict": self.verdict.value,
            "tier": self.tier.label if self.tier is not None else None,
            "reasons": [r.as_dict() for r in self.reasons],
            "required_approvals": list(self.required_approvals),
            "incidents": list(self.incidents),
            "request_id": self.request_id,
            "authorization_id": self.authorization_id,
            "target": self.target,
            "action": self.action,
            "evaluated_at": self.evaluated_at.isoformat(),
        }
