"""In-memory engagement store and supporting domain objects.

This is intentionally behind small, explicit interfaces so it can be swapped
for a persistent, encrypted store (per §12) without touching the routers. All
mutable structures are guarded by locks; the policy engine's own budgets and
kill switch are already thread-safe.
"""

from __future__ import annotations

import threading
import uuid
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone

from aegis.policy import (
    ActionRequest,
    Authorization,
    AuthorizationValidator,
    PolicyConfig,
    PolicyDecision,
    PolicyEngine,
    ReasonCode,
    SignatureVerifier,
    normalize_host,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _safe_host(target: str) -> str:
    try:
        return normalize_host(target)
    except ValueError:
        return (target or "").strip().lower().rstrip(".")


class DuplicateEngagementError(Exception):
    """Raised when registering an authorization_id that already exists."""


# Reasons that block *registration* of an authorization (as opposed to a
# specific action). Time-window issues are deliberately excluded: an engagement
# whose window opens in the future is legitimate; decisions simply escalate
# until it is live.
REGISTRATION_BLOCKING = {
    ReasonCode.NO_AUTHORIZATION,
    ReasonCode.OWNERSHIP_PROOF_MISSING,
    ReasonCode.SIGNATURE_MISSING,
    ReasonCode.SIGNATURE_INVALID,
}


def registration_reasons(
    auth: Authorization, verifier: SignatureVerifier | None, require_signature: bool
) -> list:
    validator = AuthorizationValidator(verifier=verifier, require_signature=require_signature)
    return [r for r in validator.validate(auth, _utcnow()) if r.code in REGISTRATION_BLOCKING]


# --- approvals ------------------------------------------------------------

@dataclass
class ApprovalGrant:
    grant_id: str
    action: str
    target: str  # normalized host
    tokens: frozenset[str]
    granted_by: str
    granted_at: datetime
    expires_at: datetime | None = None
    single_use: bool = False
    used: bool = False
    revoked: bool = False

    def is_active(self, now: datetime) -> bool:
        if self.revoked or self.used:
            return False
        if self.expires_at is not None and now > self.expires_at:
            return False
        return True


class ApprovalLedger:
    """Persistent approval grants, keyed by (action, target host)."""

    def __init__(self) -> None:
        self._grants: dict[str, ApprovalGrant] = {}
        self._lock = threading.Lock()

    def grant(
        self,
        *,
        action: str,
        target: str,
        tokens: list[str],
        granted_by: str,
        expires_at: datetime | None = None,
        single_use: bool = False,
    ) -> ApprovalGrant:
        grant = ApprovalGrant(
            grant_id=uuid.uuid4().hex,
            action=action,
            target=_safe_host(target),
            tokens=frozenset(tokens),
            granted_by=granted_by,
            granted_at=_utcnow(),
            expires_at=expires_at,
            single_use=single_use,
        )
        with self._lock:
            self._grants[grant.grant_id] = grant
        return grant

    def tokens_for(self, action: str, target: str, now: datetime) -> set[str]:
        host = _safe_host(target)
        tokens: set[str] = set()
        with self._lock:
            for grant in self._grants.values():
                if grant.action == action and grant.target == host and grant.is_active(now):
                    tokens |= set(grant.tokens)
        return tokens

    def consume_single_use(self, action: str, target: str, now: datetime) -> None:
        host = _safe_host(target)
        with self._lock:
            for grant in self._grants.values():
                if (
                    grant.action == action
                    and grant.target == host
                    and grant.single_use
                    and grant.is_active(now)
                ):
                    grant.used = True

    def revoke(self, grant_id: str) -> bool:
        with self._lock:
            grant = self._grants.get(grant_id)
            if grant is None or grant.revoked:
                return False
            grant.revoked = True
            return True

    def list(self) -> list[ApprovalGrant]:
        with self._lock:
            return list(self._grants.values())


# --- audit ----------------------------------------------------------------

class AuditBuffer:
    """Bounded ring buffer of decision records (the audit sink)."""

    def __init__(self, maxlen: int = 1000) -> None:
        self._records: deque[dict] = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def record(self, decision: PolicyDecision) -> None:
        with self._lock:
            self._records.append(decision.as_dict())

    def recent(self, limit: int = 100) -> list[dict]:
        with self._lock:
            items = list(self._records)
        return items[-limit:]


# --- decisions cache ------------------------------------------------------

@dataclass
class StoredDecision:
    decision: PolicyDecision
    request: ActionRequest
    created_at: datetime = field(default_factory=_utcnow)
    committed: bool = False


# --- engagement -----------------------------------------------------------

class Engagement:
    def __init__(
        self,
        *,
        authorization: Authorization,
        engine: PolicyEngine,
        audit: AuditBuffer,
        max_decisions_cached: int = 500,
    ) -> None:
        self.id = authorization.authorization_id
        self.authorization = authorization
        self.engine = engine
        self.audit = audit
        self.approvals = ApprovalLedger()
        self.created_at = _utcnow()
        self.status = "active"
        self._decisions: "OrderedDict[str, StoredDecision]" = OrderedDict()
        self._max_decisions = max_decisions_cached
        self._lock = threading.Lock()

    @property
    def is_active(self) -> bool:
        return self.status == "active"

    def close(self) -> None:
        self.status = "closed"

    def remember_decision(self, stored: StoredDecision) -> None:
        with self._lock:
            self._decisions[stored.request.request_id] = stored
            while len(self._decisions) > self._max_decisions:
                self._decisions.popitem(last=False)

    def get_decision(self, request_id: str) -> StoredDecision | None:
        with self._lock:
            return self._decisions.get(request_id)


# --- store ----------------------------------------------------------------

class EngagementStore:
    def __init__(
        self,
        *,
        verifier: SignatureVerifier,
        require_signature: bool,
        max_audit_records: int = 1000,
        max_decisions_cached: int = 500,
    ) -> None:
        self._engagements: dict[str, Engagement] = {}
        self._lock = threading.Lock()
        self._verifier = verifier
        self._require_signature = require_signature
        self._max_audit = max_audit_records
        self._max_decisions = max_decisions_cached

    def create(self, authorization: Authorization) -> Engagement:
        with self._lock:
            if authorization.authorization_id in self._engagements:
                raise DuplicateEngagementError(authorization.authorization_id)
            audit = AuditBuffer(self._max_audit)
            engine = PolicyEngine(
                authorization=authorization,
                verifier=self._verifier,
                config=PolicyConfig(require_signature=self._require_signature),
                audit=audit.record,
            )
            engagement = Engagement(
                authorization=authorization,
                engine=engine,
                audit=audit,
                max_decisions_cached=self._max_decisions,
            )
            self._engagements[engagement.id] = engagement
            return engagement

    def get(self, engagement_id: str) -> Engagement | None:
        with self._lock:
            return self._engagements.get(engagement_id)

    def list(self) -> list[Engagement]:
        with self._lock:
            return list(self._engagements.values())
