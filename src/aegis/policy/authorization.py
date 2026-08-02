"""The machine-readable authorization object and its structural validator (§4).

No active action is permitted without a valid authorization object. This module
models the object with pydantic (so malformed input is rejected at parse time,
``extra="forbid"``) and provides :class:`AuthorizationValidator`, which checks
the *authorization-level* validity that is independent of any single action:
ownership proof present, time window current, and signature authentic.

Per-action checks (target in scope, action permitted/prohibited, budget) live in
the engine, which composes this with the other guards.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .decisions import Reason, ReasonCode, Verdict
from .scope import ScopeGuard
from .signing import SignatureVerifier


class Environment(str, Enum):
    STAGING = "staging"
    APPROVED_PRODUCTION = "approved-production"


class RateLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requests_per_second: float = Field(gt=0)
    max_concurrent_sessions: int = Field(ge=1)


class DataHandling(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stop_on_real_pii: bool = True
    evidence_retention_days: int = Field(default=30, ge=0)
    region: str = "eu"


class TestIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: str
    creds_ref: str


def _as_utc(value: datetime) -> datetime:
    """Coerce naive datetimes to UTC; normalise aware ones to UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class Authorization(BaseModel):
    """A signed grant of permission to test specific targets for a time window."""

    model_config = ConfigDict(extra="forbid")

    customer_id: str
    authorization_id: str
    ownership_proof: list[str] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)
    environment: Environment = Environment.STAGING
    valid_from: datetime
    valid_until: datetime
    permitted_actions: list[str] = Field(default_factory=list)
    prohibited_actions: list[str] = Field(default_factory=list)
    rate_limits: RateLimits
    approval_required_for: list[str] = Field(default_factory=list)
    test_identities: list[TestIdentity] = Field(default_factory=list)
    data_handling: DataHandling = Field(default_factory=DataHandling)
    escalation_contacts: list[str] = Field(default_factory=list)
    kill_switch_channel: str | None = None
    spend_budget: float | None = None

    # Signature envelope (not covered by the signature itself).
    signature: str | None = None
    signing_key_id: str | None = None

    @field_validator("valid_from", "valid_until")
    @classmethod
    def _tz_aware(cls, v: datetime) -> datetime:
        return _as_utc(v)

    @model_validator(mode="after")
    def _window_ordered(self) -> "Authorization":
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")
        return self

    # --- convenience predicates (pure; the engine composes these) ---

    def is_time_valid(self, now: datetime) -> bool:
        now = _as_utc(now)
        return self.valid_from <= now <= self.valid_until

    def permits(self, action: str) -> bool:
        return action in self.permitted_actions

    def prohibits(self, action: str) -> bool:
        return action in self.prohibited_actions

    def requires_approval(self, action: str) -> bool:
        return action in self.approval_required_for

    def covers_target(self, host: str) -> bool:
        # Wildcard-aware, matching ScopeGuard semantics, so authorizations
        # derived from wildcard bounty scopes (e.g. "*.example.com") work.
        return ScopeGuard(self.targets).is_allowed(host)

    def signing_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class AuthorizationValidator:
    """Validates the authorization object itself, independent of any action."""

    def __init__(
        self,
        verifier: SignatureVerifier | None = None,
        require_signature: bool = True,
    ) -> None:
        self._verifier = verifier
        self._require_signature = require_signature

    def validate(self, auth: Authorization | None, now: datetime) -> list[Reason]:
        """Return the reasons the authorization is invalid; empty == valid.

        All failures at this level are ``ESCALATE`` (stop and ask a human),
        except a bad signature, which is ``DENY`` — a tampered or forged object
        is never a judgement call.
        """
        reasons: list[Reason] = []
        if auth is None:
            return [Reason(ReasonCode.NO_AUTHORIZATION, "no authorization object", Verdict.ESCALATE)]

        now = _as_utc(now)

        if not auth.ownership_proof:
            reasons.append(
                Reason(
                    ReasonCode.OWNERSHIP_PROOF_MISSING,
                    "authorization has no ownership_proof",
                    Verdict.ESCALATE,
                )
            )

        if now < auth.valid_from:
            reasons.append(
                Reason(
                    ReasonCode.AUTHORIZATION_NOT_YET_VALID,
                    f"authorization not valid until {auth.valid_from.isoformat()}",
                    Verdict.ESCALATE,
                )
            )
        elif now > auth.valid_until:
            reasons.append(
                Reason(
                    ReasonCode.AUTHORIZATION_EXPIRED,
                    f"authorization expired at {auth.valid_until.isoformat()}",
                    Verdict.ESCALATE,
                )
            )

        if self._require_signature:
            if not auth.signature:
                reasons.append(
                    Reason(
                        ReasonCode.SIGNATURE_MISSING,
                        "authorization is unsigned but signatures are required",
                        Verdict.ESCALATE,
                    )
                )
            elif self._verifier is None or not self._verifier.verify(
                auth.signing_payload(), auth.signature, auth.signing_key_id
            ):
                reasons.append(
                    Reason(
                        ReasonCode.SIGNATURE_INVALID,
                        "authorization signature failed verification",
                        Verdict.DENY,
                    )
                )

        return reasons
