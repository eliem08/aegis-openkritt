"""Escalation queue for human-in-the-loop (Master Prompt §10)."""

from __future__ import annotations

import uuid
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from aegis.model import PlannedAction


class EscalationReason(str, Enum):
    APPROVAL_REQUIRED = "approval_required"
    POLICY_ESCALATE = "policy_escalate"
    SENSITIVE_DATA = "sensitive_data_encountered"
    PROOF_UNVERIFIABLE = "proof_unverifiable"
    KILL_SWITCH = "kill_switch"


class EscalationItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    item_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    reason: EscalationReason
    detail: str = ""
    action: PlannedAction | None = None
    decision: dict | None = None
    required_approvals: list[str] = Field(default_factory=list)
    contacts: list[str] = Field(default_factory=list)


class EscalationQueue:
    def __init__(self, contacts: list[str] | None = None) -> None:
        self._items: list[EscalationItem] = []
        self._contacts = list(contacts or [])

    def add(
        self,
        reason: EscalationReason,
        *,
        detail: str = "",
        action: PlannedAction | None = None,
        decision: dict | None = None,
        required_approvals: list[str] | None = None,
    ) -> EscalationItem:
        item = EscalationItem(
            reason=reason,
            detail=detail,
            action=action,
            decision=decision,
            required_approvals=list(required_approvals or []),
            contacts=list(self._contacts),
        )
        self._items.append(item)
        return item

    def items(self) -> list[EscalationItem]:
        return list(self._items)

    def __len__(self) -> int:
        return len(self._items)
