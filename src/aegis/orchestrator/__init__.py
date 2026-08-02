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
    "EscalationItem",
    "EscalationQueue",
    "EscalationReason",
    "GateDecision",
    "LocalGate",
    "PolicyGate",
    "BlockedAction",
    "EngagementRun",
    "Orchestrator",
    "SafetyEvent",
    "Planner",
    "ReconThenProbePlanner",
    "StaticPlanner",
    "TriageResult",
    "triage",
    "PassiveReconWorker",
    "ScriptedWorker",
    "Worker",
    "WorkerContext",
    "WorkerRegistry",
    "WorkerResult",
]

# RemoteGate needs httpx (api/dev extras). Keep the core importable without it.
try:
    from .remote import RemoteDecision, RemoteGate

    __all__ += ["RemoteDecision", "RemoteGate"]
except ModuleNotFoundError:  # pragma: no cover - httpx not installed
    pass
