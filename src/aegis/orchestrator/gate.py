"""The policy gate the loop talks to (Master Prompt §2 defense-in-depth).

The orchestrator does not call the policy engine directly — it calls a
:class:`PolicyGate`. This decouples the loop from *where* the gate lives:

* :class:`LocalGate` wraps an in-process :class:`~aegis.policy.PolicyEngine`.
* :class:`~aegis.orchestrator.remote.RemoteGate` calls the control-plane API
  over HTTP, so an agent worker fleet can run anywhere while decisions stay
  centralised and audited.

Both return a :class:`GateDecision` — anything exposing the verdict, required
approvals, incidents, request id, an ``allowed`` flag, and ``as_dict()``.
:class:`~aegis.policy.PolicyDecision` already satisfies it.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from aegis.policy import ActionRequest, PolicyEngine, Verdict


@runtime_checkable
class GateDecision(Protocol):
    verdict: Verdict
    required_approvals: list[str]
    incidents: list[str]
    request_id: str | None

    @property
    def allowed(self) -> bool:
        ...

    def as_dict(self) -> dict:
        ...


@runtime_checkable
class PolicyGate(Protocol):
    def authorize(self, request: ActionRequest, now: datetime | None = None) -> GateDecision:
        ...

    def commit(
        self,
        decision: GateDecision,
        request: ActionRequest | None = None,
        now: datetime | None = None,
    ) -> None:
        ...


class LocalGate:
    """Adapts an in-process :class:`PolicyEngine` to the gate interface."""

    def __init__(self, engine: PolicyEngine) -> None:
        self.engine = engine

    def authorize(self, request: ActionRequest, now: datetime | None = None) -> GateDecision:
        return self.engine.authorize(request, now=now)

    def commit(
        self,
        decision: GateDecision,
        request: ActionRequest | None = None,
        now: datetime | None = None,
    ) -> None:
        self.engine.commit(decision, request=request, now=now)
