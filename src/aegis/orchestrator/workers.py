"""Worker abstraction and test/mock implementations (Master Prompt §6).

Real workers are typed, bounded tools (passive_recon, api_agent, browser_agent,
template_scanner, code_analysis, fuzzer, ...). Each runs *only* after the
orchestrator has an ALLOW from the policy engine for the action. This module
defines the contract plus deterministic stand-ins so the loop is runnable and
testable without live tooling.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from aegis.model import AttackSurface, Candidate, EvidenceBundle, PlannedAction


class WorkerResult(BaseModel):
    """What a worker returns: discoveries, candidates, and evidence.

    ``sensitive_data_encountered`` signals the §5 stop condition — the
    orchestrator halts that path, records a safety event, and does not store the
    raw candidates/evidence from it.
    """

    model_config = ConfigDict(extra="forbid")

    candidates: list[Candidate] = Field(default_factory=list)
    evidence: list[EvidenceBundle] = Field(default_factory=list)
    surface_delta: AttackSurface | None = None
    sensitive_data_encountered: bool = False
    notes: str = ""


@dataclass
class WorkerContext:
    engagement_id: str
    surface: AttackSurface
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@runtime_checkable
class Worker(Protocol):
    name: str

    def run(self, action: PlannedAction, ctx: WorkerContext) -> WorkerResult:
        ...


class WorkerRegistry:
    def __init__(self) -> None:
        self._workers: dict[str, Worker] = {}

    def register(self, worker: Worker) -> None:
        self._workers[worker.name] = worker

    def get(self, name: str) -> Worker | None:
        return self._workers.get(name)

    def __contains__(self, name: str) -> bool:
        return name in self._workers


# --- deterministic stand-ins ---------------------------------------------

class ScriptedWorker:
    """Returns pre-baked results per action name (or a default).

    A stand-in for a real tool: given ``{action_name: WorkerResult}`` (or a
    callable), it echoes the scripted result so the loop can be exercised
    end-to-end deterministically.
    """

    def __init__(
        self,
        name: str,
        results: dict[str, WorkerResult] | None = None,
        default: WorkerResult | None = None,
        handler: Callable[[PlannedAction, WorkerContext], WorkerResult] | None = None,
    ) -> None:
        self.name = name
        self._results = results or {}
        self._default = default or WorkerResult()
        self._handler = handler

    def run(self, action: PlannedAction, ctx: WorkerContext) -> WorkerResult:
        if self._handler is not None:
            return self._handler(action, ctx)
        return self._results.get(action.action, self._default)


class PassiveReconWorker:
    """Mock recon: reports the target host as an asset with a couple of routes."""

    name = "passive_recon"

    def run(self, action: PlannedAction, ctx: WorkerContext) -> WorkerResult:
        from aegis.model import Asset, Parameter, ParameterLocation, Route
        from aegis.policy import normalize_host

        try:
            host = normalize_host(action.target)
        except ValueError:
            host = action.target

        asset = Asset(
            host=host,
            kind="api",
            technologies=["nginx", "fastapi"],
            routes=[
                Route(method="GET", path="/health"),
                Route(
                    method="GET",
                    path="/users/{id}",
                    parameters=[Parameter(name="id", location=ParameterLocation.PATH)],
                ),
            ],
        )
        return WorkerResult(surface_delta=AttackSurface(assets=[asset]), notes="surface mapped")
