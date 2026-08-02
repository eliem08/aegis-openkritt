"""DetectorWorker — runs detectors inside the orchestrator loop (§3, §6).

Bridges the detector framework to the orchestrator's ``Worker`` contract: builds
a gated (scope-enforcing) client per target, runs every applicable detector, and
returns the candidates + evidence as a ``WorkerResult``. Requests blocked by the
per-request gate or the scope proxy are skipped safely.
"""

from __future__ import annotations

from typing import Callable

import httpx

from aegis.netgate import ScopeViolation
from aegis.orchestrator import WorkerContext, WorkerResult
from aegis.policy import normalize_host

from .base import DetectionResult, DetectorContext, DetectorRegistry, GateBlocked, GateFn, Identity


def _host(target: str) -> str:
    try:
        return normalize_host(target)
    except ValueError:
        return target


class DetectorWorker:
    name = "detector"

    def __init__(
        self,
        registry: DetectorRegistry,
        *,
        client_factory: Callable[[str], httpx.Client],
        identities: list[Identity] | None = None,
        gate: GateFn | None = None,
        base_url_for: Callable[[str], str] | None = None,
    ) -> None:
        self._registry = registry
        self._client_factory = client_factory
        self._identities = identities or []
        self._gate = gate
        self._base_url_for = base_url_for

    def run(self, action, ctx_orch: WorkerContext) -> WorkerResult:
        base_url = (
            self._base_url_for(action.target)
            if self._base_url_for
            else f"https://{_host(action.target)}"
        )
        client = self._client_factory(action.target)

        def make_ctx(det_action: str) -> DetectorContext:
            return DetectorContext(
                base_url=base_url,
                client=client,
                identities=self._identities,
                action=det_action,
                gate=self._gate,
                params=action.params,
            )

        result = DetectionResult()
        try:
            # Applicability is action-agnostic; gate each detector by its OWN
            # declared action so the policy engine sees the real consequence tier.
            for detector in self._registry.applicable(make_ctx(action.action)):
                try:
                    result.extend(detector.run(make_ctx(detector.action)))
                except (GateBlocked, ScopeViolation):
                    continue  # blocked request; skip this detector safely
        finally:
            client.close()

        return WorkerResult(
            candidates=result.candidates,
            evidence=result.evidence,
            sensitive_data_encountered=result.sensitive_data_encountered,
            notes=f"{len(result.candidates)} candidate(s) from detectors",
        )
