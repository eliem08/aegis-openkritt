"""Core contracts for the agent-first Aegis/Jarvis runtime."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AgentRole(str, Enum):
    COMMANDER = "commander"
    POLICY = "policy"
    RECON = "recon"
    REPOSITORY_INTELLIGENCE = "repository_intelligence"
    ATTACK_SURFACE = "attack_surface"
    STATIC_ANALYSIS = "static_analysis"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    BUSINESS_LOGIC = "business_logic"
    API = "api"
    CLIENT = "client"
    SUPPLY_CHAIN = "supply_chain"
    CLOUD = "cloud"
    INVARIANT = "invariant"
    HYPOTHESIS = "hypothesis"
    PATCH_VARIANT = "patch_variant"
    COVERAGE = "coverage"
    REPRODUCTION = "reproduction"
    EVIDENCE = "evidence"
    SKEPTIC = "skeptic"
    PROFITABILITY = "profitability"
    REPORTING = "reporting"


class RiskClass(str, Enum):
    READ_ONLY = "read_only"
    CONTROLLED_STATE_CHANGE = "controlled_state_change"
    HIGH_RISK = "high_risk"


class EvidenceStage(str, Enum):
    CANDIDATE = "candidate"
    SOURCE_SUPPORTED = "source_supported"
    RUNTIME_OBSERVED = "runtime_observed"
    REPRODUCED = "reproduced"
    INDEPENDENTLY_VERIFIED = "independently_verified"
    HUMAN_APPROVED = "human_approved"
    SUBMISSION_READY = "submission_ready"


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
