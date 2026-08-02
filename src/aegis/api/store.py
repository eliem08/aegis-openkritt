"""Engagement store + supporting domain objects.

Behind a small interface (§12) so it runs purely in-memory *or* write-through to
a durable :class:`Repository` (SQLite today, Postgres later — same protocol).
With a repository, engagements, approval grants, the audit trail, kill-switch
state, and spend budget survive a restart; the store rehydrates a live
``PolicyEngine`` on demand. Rate/concurrency budgets and the uncommitted-decision
cache are runtime-only and reset on restart (documented, conservative).
"""

from __future__ import annotations

import threading
import uuid
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Protocol, runtime_checkable

from aegis.policy import (
    ActionRequest,
    Authorization,
    AuthorizationValidator,
    KillSwitch,
    PolicyConfig,
    PolicyDecision,
    PolicyEngine,
    ReasonCode,
    SignatureVerifier,
    SpendBudget,
    normalize_host,
)
from aegis.policy.killswitch import KillSwitchState


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _safe_host(target: str) -> str:
    try:
        return normalize_host(target)
    except ValueError:
        return (target or "").strip().lower().rstrip(".")


class DuplicateEngagementError(Exception):
    """Raised when registering an authorization_id that already exists."""


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


# --- persistence contract -------------------------------------------------

@dataclass
class EngagementRecord:
    id: str
    authorization: dict
    status: str
    created_at: datetime


@runtime_checkable
class Repository(Protocol):
    """Durable backing store. A SQLite implementation lives in
    :mod:`aegis.api.persistence`; Postgres would implement the same protocol."""

    def save_engagement(self, record: EngagementRecord) -> None: ...
    def get_engagement(self, engagement_id: str) -> EngagementRecord | None: ...
    def list_engagement_ids(self) -> list[str]: ...
    def update_engagement_status(self, engagement_id: str, status: str) -> None: ...

    def save_grant(self, engagement_id: str, grant: "ApprovalGrant") -> None: ...
    def list_grants(self, engagement_id: str) -> list["ApprovalGrant"]: ...

    def append_audit(self, engagement_id: str, record: dict) -> None: ...
    def recent_audit(self, engagement_id: str, limit: int) -> list[dict]: ...

    def save_kill_state(self, engagement_id: str, state: KillSwitchState) -> None: ...
    def get_kill_state(self, engagement_id: str) -> KillSwitchState | None: ...

    def save_spend(self, engagement_id: str, spent: float) -> None: ...
    def get_spend(self, engagement_id: str) -> float | None: ...


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
    """Approval grants keyed by (action, target host).

    ``on_change`` is fired (with the changed grant) after grant/revoke/consume so
    the store can persist it.
    """

    def __init__(
        self,
        initial: list[ApprovalGrant] | None = None,
        on_change: Callable[[ApprovalGrant], None] | None = None,
    ) -> None:
        self._grants: dict[str, ApprovalGrant] = {g.grant_id: g for g in (initial or [])}
        self._lock = threading.Lock()
        self._on_change = on_change

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
        self._notify(grant)
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
        changed: list[ApprovalGrant] = []
        with self._lock:
            for grant in self._grants.values():
                if (
                    grant.action == action
                    and grant.target == host
                    and grant.single_use
                    and grant.is_active(now)
                ):
                    grant.used = True
                    changed.append(grant)
        for grant in changed:
            self._notify(grant)

    def revoke(self, grant_id: str) -> bool:
        with self._lock:
            grant = self._grants.get(grant_id)
            if grant is None or grant.revoked:
                return False
            grant.revoked = True
        self._notify(grant)
        return True

    def list(self) -> list[ApprovalGrant]:
        with self._lock:
            return list(self._grants.values())

    def _notify(self, grant: ApprovalGrant) -> None:
        if self._on_change is not None:
            self._on_change(grant)


# --- audit ----------------------------------------------------------------

class AuditBuffer:
    """Bounded ring buffer of decision records (the engine's audit sink).

    ``on_record`` is fired with each record dict so the store can persist the
    (durable, append-only) audit trail.
    """

    def __init__(
        self, maxlen: int = 1000, on_record: Callable[[dict], None] | None = None
    ) -> None:
        self._records: deque[dict] = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._on_record = on_record

    def record(self, decision: PolicyDecision) -> None:
        entry = decision.as_dict()
        with self._lock:
            self._records.append(entry)
        if self._on_record is not None:
            self._on_record(entry)

    def preload(self, records: list[dict]) -> None:
        with self._lock:
            for record in records:
                self._records.append(record)

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
        approvals: ApprovalLedger | None = None,
        status: str = "active",
        created_at: datetime | None = None,
        max_decisions_cached: int = 500,
        on_status_change: Callable[[str], None] | None = None,
    ) -> None:
        self.id = authorization.authorization_id
        self.authorization = authorization
        self.engine = engine
        self.audit = audit
        self.approvals = approvals if approvals is not None else ApprovalLedger()
        self.created_at = created_at or _utcnow()
        self.status = status
        self._decisions: "OrderedDict[str, StoredDecision]" = OrderedDict()
        self._max_decisions = max_decisions_cached
        self._lock = threading.Lock()
        self._on_status_change = on_status_change

    @property
    def is_active(self) -> bool:
        return self.status == "active"

    def close(self) -> None:
        self.status = "closed"
        if self._on_status_change is not None:
            self._on_status_change("closed")

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
        repository: Repository | None = None,
    ) -> None:
        self._live: dict[str, Engagement] = {}
        self._lock = threading.Lock()
        self._verifier = verifier
        self._require_signature = require_signature
        self._max_audit = max_audit_records
        self._max_decisions = max_decisions_cached
        self._repo = repository

    # -- construction / rehydration --

    def _build_engagement(
        self,
        auth: Authorization,
        *,
        status: str = "active",
        created_at: datetime | None = None,
        restore: dict | None = None,
    ) -> Engagement:
        eid = auth.authorization_id
        repo = self._repo

        audit = AuditBuffer(
            self._max_audit,
            on_record=(lambda d, _e=eid: repo.append_audit(_e, d)) if repo else None,
        )
        if restore and restore.get("audit"):
            audit.preload(restore["audit"])

        approvals = ApprovalLedger(
            initial=restore.get("grants") if restore else None,
            on_change=(lambda g, _e=eid: repo.save_grant(_e, g)) if repo else None,
        )

        kill = KillSwitch(on_change=(lambda st, _e=eid: repo.save_kill_state(_e, st)) if repo else None)
        if restore and restore.get("kill"):
            kill.restore(restore["kill"])

        spend = None
        if auth.spend_budget is not None:
            spent = (restore.get("spent") if restore else 0.0) or 0.0
            spend = SpendBudget(
                auth.spend_budget,
                spent=spent,
                on_change=(lambda total, _e=eid: repo.save_spend(_e, total)) if repo else None,
            )

        engine = PolicyEngine(
            authorization=auth,
            verifier=self._verifier,
            config=PolicyConfig(require_signature=self._require_signature),
            audit=audit.record,
            kill_switch=kill,
            spend_budget=spend,
        )
        return Engagement(
            authorization=auth,
            engine=engine,
            audit=audit,
            approvals=approvals,
            status=status,
            created_at=created_at,
            max_decisions_cached=self._max_decisions,
            on_status_change=(lambda s, _e=eid: repo.update_engagement_status(_e, s)) if repo else None,
        )

    # -- public API --

    def create(self, authorization: Authorization) -> Engagement:
        eid = authorization.authorization_id
        with self._lock:
            if eid in self._live:
                raise DuplicateEngagementError(eid)
        if self._repo is not None and self._repo.get_engagement(eid) is not None:
            raise DuplicateEngagementError(eid)

        engagement = self._build_engagement(authorization, status="active", created_at=_utcnow())
        if self._repo is not None:
            self._repo.save_engagement(
                EngagementRecord(
                    id=eid,
                    authorization=authorization.model_dump(mode="json"),
                    status="active",
                    created_at=engagement.created_at,
                )
            )
        with self._lock:
            if eid in self._live:
                raise DuplicateEngagementError(eid)
            self._live[eid] = engagement
        return engagement

    def get(self, engagement_id: str) -> Engagement | None:
        with self._lock:
            engagement = self._live.get(engagement_id)
        if engagement is not None:
            return engagement
        if self._repo is None:
            return None
        return self._rehydrate(engagement_id)

    def list(self) -> list[Engagement]:
        with self._lock:
            ids = set(self._live.keys())
        if self._repo is not None:
            ids |= set(self._repo.list_engagement_ids())
        result = []
        for eid in ids:
            engagement = self.get(eid)
            if engagement is not None:
                result.append(engagement)
        return result

    def _rehydrate(self, engagement_id: str) -> Engagement | None:
        record = self._repo.get_engagement(engagement_id)
        if record is None:
            return None
        auth = Authorization(**record.authorization)
        restore = {
            "grants": self._repo.list_grants(engagement_id),
            "audit": self._repo.recent_audit(engagement_id, self._max_audit),
            "kill": self._repo.get_kill_state(engagement_id),
            "spent": self._repo.get_spend(engagement_id) or 0.0,
        }
        with self._lock:
            existing = self._live.get(engagement_id)
            if existing is not None:
                return existing
            engagement = self._build_engagement(
                auth, status=record.status, created_at=record.created_at, restore=restore
            )
            self._live[engagement_id] = engagement
            return engagement
