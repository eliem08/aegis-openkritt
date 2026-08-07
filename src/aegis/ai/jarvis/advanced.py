"""Advanced Aegis Jarvis specialist council.

This module composes autonomous reasoning agents without granting them direct
execution authority. Every action proposal remains subject to the central
proposal policy and active authorization envelope.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from ..agentic_os import (
    AgentContext,
    AgenticOrchestrator,
    AgentProposal,
    AgentRole,
    RiskClass,
    SecurityAgent,
)
from ..portfolio_agents import ProfitabilityAgent
from ..research_agents import (
    AuthorizationAgent,
    BusinessLogicAgent,
    EvidenceAgent,
    HistoryVariantAgent,
    HypothesisAgent,
    InvariantAgent,
    JudgeAgent,
    ReproductionAgent,
)
from .learning_agents import (
    CoverageOptimizerAgent,
    MissionSchedulerAgent,
    OutcomeLearningAgent,
    RuleSynthesisAgent,
    VulnerabilityFamilyAgent,
)
from .profit_controls import StopLossAgent
from .state_store import JarvisStateStore
from .weakness_planner import ChainReasoningAgent, UniversalHuntAgent


@dataclass(frozen=True)
class MemoryTriggeredAgent:
    role: AgentRole
    memory_key: str
    action: str
    rationale: str
    information_gain: float
    risk: RiskClass = RiskClass.OFFLINE
    requires_network: bool = False
    expected_requests: int = 0

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]:
        item = context.memory.get(self.memory_key)
        if item is None or item.value in (None, (), [], {}, ""):
            return ()
        return (
            AgentProposal(
                role=self.role,
                action=self.action,
                rationale=self.rationale,
                risk=self.risk,
                expected_information_gain=self.information_gain,
                requires_network=self.requires_network,
                expected_requests=self.expected_requests,
                metadata={"memory_key": self.memory_key},
            ),
        )


def default_agents(
    *,
    human_hour_cost_usd: float = 0.0,
    state_store: JarvisStateStore | None = None,
) -> tuple[SecurityAgent, ...]:
    """Return the advanced specialist council used by the Jarvis orchestrator."""
    return (
        MissionSchedulerAgent(),
        StopLossAgent(),
        MemoryTriggeredAgent(
            AgentRole.PROGRAM_POLICY,
            "program:policy",
            "review_program_policy",
            "Re-evaluate scope, exclusions, automation limits, and disclosure constraints.",
            1.0,
        ),
        MemoryTriggeredAgent(
            AgentRole.ASSET_DISCOVERY,
            "assets:seed",
            "expand_authorized_asset_graph",
            "Expand only signed in-scope seed assets and preserve discovery provenance.",
            0.78,
            RiskClass.READ_ONLY,
            True,
            20,
        ),
        MemoryTriggeredAgent(
            AgentRole.REPOSITORY_INTELLIGENCE,
            "repository:profile",
            "profile_repository_security_surface",
            "Map languages, manifests, frameworks, entrypoints, routes, and trust boundaries.",
            0.82,
        ),
        MemoryTriggeredAgent(
            AgentRole.ATTACK_SURFACE,
            "attack_surface:events",
            "correlate_attack_surface_events",
            "Correlate newly discovered endpoints, services, repositories, and ownership edges.",
            0.8,
        ),
        CoverageOptimizerAgent(),
        UniversalHuntAgent(state_store=state_store),
        MemoryTriggeredAgent(
            AgentRole.STATIC_ANALYSIS,
            "scanner:candidates",
            "triage_static_candidates",
            "Prioritize high-signal static candidates by reachability and evidence quality.",
            0.72,
        ),
        RuleSynthesisAgent(),
        MemoryTriggeredAgent(
            AgentRole.DATAFLOW,
            "dataflow:paths",
            "analyze_cross_file_dataflow",
            "Reason across attacker-controlled sources, validators, sanitizers, and sensitive sinks.",
            0.9,
        ),
        MemoryTriggeredAgent(
            AgentRole.AUTHENTICATION,
            "auth:states",
            "analyze_authentication_state_machine",
            "Search for inconsistent authentication and recovery state transitions.",
            0.88,
        ),
        MemoryTriggeredAgent(
            AgentRole.API,
            "api:operations",
            "plan_stateful_api_analysis",
            "Derive bounded producer-consumer request sequences for disposable local validation.",
            0.86,
        ),
        MemoryTriggeredAgent(
            AgentRole.DEPENDENCY,
            "dependencies:findings",
            "rank_reachable_dependency_risk",
            "Prioritize dependencies only when version, call, and reachability evidence support impact.",
            0.65,
        ),
        MemoryTriggeredAgent(
            AgentRole.CLOUD,
            "cloud:surface",
            "analyze_cloud_trust_boundaries",
            "Correlate infrastructure exposure and application trust relationships without assuming live access.",
            0.7,
        ),
        MemoryTriggeredAgent(
            AgentRole.HISTORY,
            "history:security_sensitive_changes",
            "analyze_security_sensitive_history",
            "Inspect recent changes for regressions, incomplete fixes, and unexplored siblings.",
            0.89,
        ),
        HypothesisAgent(),
        InvariantAgent(),
        BusinessLogicAgent(),
        ChainReasoningAgent(),
        AuthorizationAgent(),
        HistoryVariantAgent(),
        VulnerabilityFamilyAgent(),
        ReproductionAgent(),
        EvidenceAgent(),
        JudgeAgent(),
        OutcomeLearningAgent(),
        ProfitabilityAgent(human_hour_cost_usd=human_hour_cost_usd),
        MemoryTriggeredAgent(
            AgentRole.REPORT,
            "reports:ready_findings",
            "draft_evidence_backed_report",
            "Draft a concise report only for evidence-complete, human-approved findings.",
            0.6,
        ),
    )


def build_jarvis(
    *,
    human_hour_cost_usd: float = 0.0,
    state_store: JarvisStateStore | None = None,
) -> AgenticOrchestrator:
    """Build the advanced council under centralized authorization control."""
    return AgenticOrchestrator(
        default_agents(
            human_hour_cost_usd=human_hour_cost_usd,
            state_store=state_store,
        )
    )
