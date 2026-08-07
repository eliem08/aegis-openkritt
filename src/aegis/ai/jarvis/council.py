"""Agent council and commander for an agent-first Aegis runtime."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .economics import estimate_hypothesis
from .guards import PolicyGate
from .models import (
    ActionProposal,
    AgentResult,
    AgentRole,
    HuntObjective,
    ResearchHypothesis,
    RiskClass,
    RuntimePlan,
)

DEFAULT_COUNCIL: tuple[AgentRole, ...] = (
    AgentRole.POLICY,
    AgentRole.RECON,
    AgentRole.REPOSITORY_INTELLIGENCE,
    AgentRole.ATTACK_SURFACE,
    AgentRole.STATIC_ANALYSIS,
    AgentRole.AUTHENTICATION,
    AgentRole.AUTHORIZATION,
    AgentRole.BUSINESS_LOGIC,
    AgentRole.API,
    AgentRole.CLIENT,
    AgentRole.SUPPLY_CHAIN,
    AgentRole.CLOUD,
    AgentRole.INVARIANT,
    AgentRole.HYPOTHESIS,
    AgentRole.PATCH_VARIANT,
    AgentRole.COVERAGE,
    AgentRole.REPRODUCTION,
    AgentRole.EVIDENCE,
    AgentRole.SKEPTIC,
    AgentRole.PROFITABILITY,
    AgentRole.REPORTING,
)


class CouncilAgent(Protocol):
    role: AgentRole

    def propose(self, objective: HuntObjective) -> AgentResult:
        """Return non-executable research proposals."""


@dataclass(frozen=True)
class HypothesisRanking:
    hypothesis: ResearchHypothesis
    score: float
    expected_net_usd: float


class ProfitabilityAgent:
    role = AgentRole.PROFITABILITY

    def rank(
        self,
        hypotheses: list[ResearchHypothesis],
        *,
        validity_probability: float = 0.65,
        acceptance_probability: float = 0.75,
        reproducibility_probability: float = 0.70,
        human_review_cost_usd: float = 5.0,
    ) -> tuple[HypothesisRanking, ...]:
        ranked: list[HypothesisRanking] = []
        for hypothesis in hypotheses:
            estimate = estimate_hypothesis(
                hypothesis,
                validity_probability=validity_probability,
                acceptance_probability=acceptance_probability,
                reproducibility_probability=reproducibility_probability,
                human_review_cost_usd=human_review_cost_usd,
                exploration_bonus=25.0,
            )
            ranked.append(
                HypothesisRanking(
                    hypothesis=hypothesis,
                    score=estimate.score,
                    expected_net_usd=estimate.expected_net_usd,
                )
            )
        return tuple(
            sorted(
                ranked,
                key=lambda item: (
                    item.score,
                    item.expected_net_usd,
                    item.hypothesis.confidence,
                ),
                reverse=True,
            )
        )


class SkepticAgent:
    """Independent verifier that proposes falsification work, not acceptance."""

    role = AgentRole.SKEPTIC

    def challenge(
        self,
        objective: HuntObjective,
        hypothesis: ResearchHypothesis,
    ) -> ActionProposal:
        return ActionProposal(
            agent=self.role,
            action="challenge_hypothesis",
            reason=(
                "Attempt to falsify reachability, attacker control, missing guard, impact, "
                "and duplicate assumptions before reproduction."
            ),
            scope_digest=objective.scope_digest,
            risk=RiskClass.READ_ONLY,
            estimated_cost_usd=min(
                1.0 + 0.25 * len(hypothesis.evidence_needed),
                5.0,
            ),
            information_gain=0.9,
            expected_net_value_usd=0.0,
            requires_network=False,
            requires_model_egress=objective.model_egress_authorized,
            metadata={"hypothesis_id": hypothesis.hypothesis_id},
        )


class ReproductionAgent:
    """Plans bounded reproduction; it does not execute live exploitation itself."""

    role = AgentRole.REPRODUCTION

    def propose(
        self,
        objective: HuntObjective,
        hypothesis: ResearchHypothesis,
        *,
        local_lab_available: bool,
    ) -> ActionProposal:
        return ActionProposal(
            agent=self.role,
            action="reproduce_in_disposable_lab",
            reason="Validate the security hypothesis with deterministic positive/negative controls.",
            scope_digest=objective.scope_digest,
            risk=RiskClass.READ_ONLY,
            estimated_cost_usd=hypothesis.estimated_validation_cost_usd,
            estimated_requests=min(max(len(hypothesis.validation_plan), 1), 10),
            information_gain=1.0,
            expected_net_value_usd=max(
                0.0,
                hypothesis.estimated_payout_usd
                * hypothesis.confidence
                * (1.0 - hypothesis.duplicate_probability)
                - hypothesis.estimated_validation_cost_usd,
            ),
            requires_network=False,
            requires_human_approval=not local_lab_available,
            metadata={
                "hypothesis_id": hypothesis.hypothesis_id,
                "local_lab_available": local_lab_available,
            },
        )


class EvidenceAgent:
    role = AgentRole.EVIDENCE

    def propose(
        self,
        objective: HuntObjective,
        hypothesis: ResearchHypothesis,
    ) -> ActionProposal:
        return ActionProposal(
            agent=self.role,
            action="assemble_redacted_evidence_bundle",
            reason="Create an immutable report-quality evidence package after reproduction.",
            scope_digest=objective.scope_digest,
            risk=RiskClass.READ_ONLY,
            estimated_cost_usd=0.1,
            information_gain=0.2,
            metadata={"hypothesis_id": hypothesis.hypothesis_id},
        )


class ReportAgent:
    role = AgentRole.REPORTING

    def propose(
        self,
        objective: HuntObjective,
        hypothesis: ResearchHypothesis,
    ) -> ActionProposal:
        return ActionProposal(
            agent=self.role,
            action="draft_human_review_report",
            reason="Draft a report only after evidence is reproduced and independently verified.",
            scope_digest=objective.scope_digest,
            risk=RiskClass.READ_ONLY,
            estimated_cost_usd=0.25,
            information_gain=0.1,
            requires_human_approval=True,
            metadata={"hypothesis_id": hypothesis.hypothesis_id},
        )


class JarvisCommander:
    """Schedules approved proposals while preserving deterministic safety gates."""

    role = AgentRole.COMMANDER

    def __init__(self, gate: PolicyGate | None = None) -> None:
        self._gate = gate or PolicyGate()

    def plan(
        self,
        objective: HuntObjective,
        proposals: list[ActionProposal],
        *,
        human_approved: bool = False,
    ) -> RuntimePlan:
        approved: list[ActionProposal] = []
        blocked: list[ActionProposal] = []
        spent = 0.0
        requests = 0

        ordered = sorted(
            proposals,
            key=lambda proposal: (
                proposal.expected_net_value_usd,
                proposal.information_gain,
                -proposal.estimated_cost_usd,
            ),
            reverse=True,
        )
        for proposal in ordered:
            decision = self._gate.evaluate(
                objective,
                proposal,
                spent_usd=spent,
                used_requests=requests,
                human_approved=human_approved,
            )
            if not decision.allowed:
                blocked.append(proposal)
                continue
            approved.append(proposal)
            spent += proposal.estimated_cost_usd
            requests += proposal.estimated_requests

        return RuntimePlan(
            objective=objective,
            approved=tuple(approved),
            blocked=tuple(blocked),
            total_projected_cost_usd=spent,
            total_projected_requests=requests,
        )
