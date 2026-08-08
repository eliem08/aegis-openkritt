"""Legacy Jarvis dataclasses backed by canonical ``agentic_os`` enums.

The data shapes in this module remain for compatibility with older council helpers, but role,
risk and lifecycle identity now come from one source of truth. New runtime work should prefer
``aegis.ai.agentic_os.AgentProposal`` and ``FindingLifecycle`` directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..agentic_os import AgentRole, EvidenceStage, RiskClass


@dataclass(frozen=True)
class HuntObjective:
    program_id: str
    target: str
    scope_digest: str
    maximum_cost_usd: float
    maximum_requests: int
    network_authorized: bool = False
    state_change_authorized: bool = False
    model_egress_authorized: bool = False


@dataclass(frozen=True)
class ActionProposal:
    """Compatibility proposal shape for the legacy council.

    It uses canonical enums but is intentionally not a second action authority. Execution gates
    remain in ``agentic_os.ProposalPolicy`` for the live Jarvis runtime.
    """

    agent: AgentRole
    action: str
    reason: str
    scope_digest: str
    risk: RiskClass = RiskClass.READ_ONLY
    estimated_cost_usd: float = 0.0
    estimated_requests: int = 0
    information_gain: float = 0.0
    expected_net_value_usd: float = 0.0
    requires_network: bool = False
    requires_model_egress: bool = False
    requires_human_approval: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class SecurityInvariant:
    invariant_id: str
    component: str
    statement: str
    confidence: float
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class ResearchHypothesis:
    hypothesis_id: str
    title: str
    weakness: str
    invariant_id: str | None
    rationale: str
    confidence: float
    novelty_score: float
    duplicate_probability: float
    estimated_payout_usd: float
    estimated_validation_cost_usd: float
    evidence_needed: tuple[str, ...] = ()
    validation_plan: tuple[str, ...] = ()


@dataclass(frozen=True)
class FindingState:
    finding_id: str
    stage: EvidenceStage
    confidence: float
    evidence_refs: tuple[str, ...] = ()
    reviewer: str | None = None


@dataclass(frozen=True)
class AgentResult:
    agent: AgentRole
    summary: str
    proposals: tuple[ActionProposal, ...] = ()
    invariants: tuple[SecurityInvariant, ...] = ()
    hypotheses: tuple[ResearchHypothesis, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RuntimePlan:
    objective: HuntObjective
    approved: tuple[ActionProposal, ...]
    blocked: tuple[ActionProposal, ...]
    total_projected_cost_usd: float
    total_projected_requests: int
