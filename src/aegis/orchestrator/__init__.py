"""The orchestrator loop and its collaborators (Master Prompt §3).

Every planned action is gated by ``aegis.policy`` before a worker runs it.
"""

from .escalation import EscalationItem, EscalationQueue, EscalationReason
from .gate import GateDecision, LocalGate, PolicyGate
from .loop import BlockedAction, EngagementRun, Orchestrator, SafetyEvent
from .planner import Planner, ReconThenProbePlanner, StaticPlanner
from .triage import TriageResult, triage
from .workers import (
    PassiveReconWorker,
    ScriptedWorker,
    Worker,
    WorkerContext,
    WorkerRegistry,
    WorkerResult,
)

__all__ = [
    "BlockedAction",
    "EngagementRun",
    "EscalationItem",
    "EscalationQueue",
    "EscalationReason",
    "GateDecision",
    "LocalGate",
    "Orchestrator",
    "PassiveReconWorker",
    "Planner",
    "PolicyGate",
    "ReconThenProbePlanner",
    "SafetyEvent",
    "ScriptedWorker",
    "StaticPlanner",
    "TriageResult",
    "Worker",
    "WorkerContext",
    "WorkerRegistry",
    "WorkerResult",
    "triage",
]

# RemoteGate needs httpx (api/dev extras). Keep the core importable without it.
try:
    from .remote import RemoteDecision, RemoteGate

    __all__ += ["RemoteDecision", "RemoteGate"]
except ModuleNotFoundError:  # pragma: no cover - httpx not installed
    pass
