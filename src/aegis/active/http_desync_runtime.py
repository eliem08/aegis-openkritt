"""Bounded executor adapter for HTTP desync validation.

The adapter deliberately does not know how to craft unrestricted smuggling payloads.  It binds
Jarvis's approved ``DetectorTask`` to a configured, scope-controlled validator and converts the
validator's structured differential result into canonical immutable evidence.

A deployment that has no approved validator must not register this executor; ``active_runtime``
will then report ``executor_missing`` and perform no network action.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Protocol

from aegis.ai.active_runtime import ActiveExecutionContext, ActiveExecutionResult
from aegis.ai.agentic_os import EvidenceRef

from .detectors import DetectorTask


@dataclass(frozen=True)
class DesyncValidationResult:
    route: str
    family: str
    observed: bool
    reproducible: bool = False
    requests_used: int = 0
    summary: str = ""
    observation_digest: str = ""


class DesyncValidator(Protocol):
    """Deployment-owned, already-scoped validator contract."""

    def validate(
        self,
        *,
        route: str,
        family: str,
        max_requests: int,
    ) -> DesyncValidationResult: ...


class HttpDesyncExecutor:
    """Execute only the evidence-backed candidates embedded in an approved detector task."""

    def __init__(self, validator: DesyncValidator) -> None:
        self._validator = validator

    def execute(
        self,
        task: DetectorTask,
        context: ActiveExecutionContext,
    ) -> ActiveExecutionResult:
        if task.detector != "http_desync":
            raise ValueError("HttpDesyncExecutor received a non-http_desync task")
        candidates = list((task.config or {}).get("candidates") or [])
        if not candidates:
            return ActiveExecutionResult(status="no_candidates")

        allowed_targets = set(task.targets)
        request_cap = max(0, min(int(task.est_requests), context.authorization.budget.max_requests))
        if request_cap <= 0:
            return ActiveExecutionResult(status="budget_exhausted")

        evidence: list[EvidenceRef] = []
        used = 0
        observed = 0
        reproduced = 0
        for candidate in candidates:
            route = str(candidate.get("route") or "")
            family = str(candidate.get("family") or "")
            if not route or route not in allowed_targets or not family:
                continue
            remaining = request_cap - used
            if remaining <= 0:
                break
            result = self._validator.validate(
                route=route,
                family=family,
                max_requests=remaining,
            )
            if result.route != route or result.family != family:
                raise RuntimeError("desync validator returned evidence for a different candidate")
            consumed = max(0, int(result.requests_used))
            if consumed > remaining:
                raise RuntimeError("desync validator exceeded its per-call request allowance")
            used += consumed
            if not result.observed:
                continue

            observed += 1
            reproduced += int(bool(result.reproducible))
            material = {
                "route": route,
                "family": family,
                "reproducible": bool(result.reproducible),
                "summary": result.summary,
                "observation_digest": result.observation_digest,
            }
            digest = hashlib.sha256(
                json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            evidence.append(
                EvidenceRef(
                    evidence_id=f"desync:{digest[:20]}",
                    kind=(
                        "http_desync_reproduced"
                        if result.reproducible
                        else "http_desync_runtime_observation"
                    ),
                    digest=digest,
                    summary=(result.summary or f"{family} differential observed on {route}")[:300],
                )
            )

        status = "reproduced" if reproduced else ("observed" if observed else "not_observed")
        return ActiveExecutionResult(
            status=status,
            evidence=tuple(evidence),
            requests_used=used,
            metadata={
                "observed": observed,
                "reproduced": reproduced,
                "candidates_considered": len(candidates),
            },
        )
