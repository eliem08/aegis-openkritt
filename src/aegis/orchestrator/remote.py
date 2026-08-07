"""Remote policy gate — drives the loop over the control-plane API (§3, §6).

``RemoteGate`` turns each policy check into an HTTP call to the control plane:
``POST /engagements/{id}/decisions`` to authorize, and
``POST /engagements/{id}/decisions/{rid}/commit`` to debit budget after an
allowed action runs. Workers still execute in-process on the agent side; only
the *gate* is remote, so decisions stay centralised, authenticated, and audited.

Requires ``httpx`` (installed with the ``api`` or ``dev`` extras). Any
``httpx.Client`` works — including FastAPI's ``TestClient`` for in-process
testing against a live ASGI app.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

import httpx

from aegis.policy import ActionRequest, Verdict


@dataclass
class RemoteDecision:
    """A :class:`~aegis.orchestrator.gate.GateDecision` built from API JSON."""

    verdict: Verdict
    required_approvals: list[str]
    incidents: list[str]
    request_id: str | None
    raw: dict

    @property
    def allowed(self) -> bool:
        return self.verdict == Verdict.ALLOW

    def as_dict(self) -> dict:
        return dict(self.raw)

    @classmethod
    def from_json(cls, data: dict) -> RemoteDecision:
        return cls(
            verdict=Verdict(data["verdict"]),
            required_approvals=list(data.get("required_approvals", [])),
            incidents=list(data.get("incidents", [])),
            request_id=data.get("request_id"),
            raw=data,
        )


class RemoteGate:
    def __init__(
        self,
        *,
        engagement_id: str,
        token: str,
        base_url: str | None = None,
        client: httpx.Client | None = None,
        timeout: float = 10.0,
    ) -> None:
        if client is None and base_url is None:
            raise ValueError("provide either base_url or an httpx client")
        self._client = client or httpx.Client(base_url=base_url, timeout=timeout)
        self._owns_client = client is None
        self._engagement_id = engagement_id
        self._headers = {"Authorization": f"Bearer {token}"}
        self._base = f"/engagements/{engagement_id}"

    def authorize(self, request: ActionRequest, now: datetime | None = None) -> RemoteDecision:
        body: dict = {
            "target": request.target,
            "action": request.action,
            "description": request.description,
            "identity": request.identity,
            "estimated_cost": request.estimated_cost,
            "touches_production": request.touches_production,
            "request_id": request.request_id,
        }
        if request.tier_hint is not None:
            body["tier_hint"] = int(request.tier_hint)
        resp = self._client.post(f"{self._base}/decisions", headers=self._headers, json=body)
        resp.raise_for_status()
        return RemoteDecision.from_json(resp.json())

    def commit(
        self,
        decision: RemoteDecision,
        request: ActionRequest | None = None,
        now: datetime | None = None,
    ) -> None:
        rid = request.request_id if request is not None else decision.request_id
        resp = self._client.post(f"{self._base}/decisions/{rid}/commit", headers=self._headers)
        resp.raise_for_status()

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> RemoteGate:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
