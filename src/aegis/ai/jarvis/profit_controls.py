"""Profit controls for severity-inclusive autonomous research planning."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from ..agentic_os import AgentContext, AgentProposal, AgentRole, RiskClass
from .weakness_catalog import HuntCandidate, SeverityTier


class CandidateDisposition(str, Enum):
    DIRECT = "direct"
    CHAIN_ONLY = "chain_only"
    IGNORE = "ignore"


@dataclass(frozen=True)
class ProgramEligibility:
    """Program-specific reward policy without discarding useful weak signals."""

    paid_severities: tuple[SeverityTier, ...] = (
        SeverityTier.LOW,
        SeverityTier.MEDIUM,
        SeverityTier.HIGH,
        SeverityTier.CRITICAL,
    )
    excluded_families: tuple[str, ...] = ()
    minimum_expected_payout_usd: float = 0.0
    keep_unpaid_chain_evidence: bool = True

    def disposition(self, candidate: HuntCandidate) -> CandidateDisposition:
        excluded = candidate.family.family_id in set(self.excluded_families)
        paid = candidate.severity in set(self.paid_severities)
        enough_value = candidate.expected_payout_usd >= self.minimum_expected_payout_usd
        if not excluded and paid and enough_value and candidate.expected_net_usd >= 0:
            return CandidateDisposition.DIRECT
        if self.keep_unpaid_chain_evidence and candidate.chainability > 0.0:
            return CandidateDisposition.CHAIN_ONLY
        return CandidateDisposition.IGNORE


@dataclass(frozen=True)
class ResearchRunMetrics:
    projected_net_usd: float
    spend_usd: float
    budget_usd: float
    evidence_gain: float
    consecutive_empty_rounds: int = 0
    duplicate_probability: float = 0.0
    novelty_score: float = 0.0
    reproduced: bool = False


@dataclass(frozen=True)
class StopLossDecision:
    continue_research: bool
    reason: str


def evaluate_stop_loss(metrics: ResearchRunMetrics) -> StopLossDecision:
    if metrics.reproduced:
        return StopLossDecision(True, "finding reproduced; continue evidence completion")
    if metrics.budget_usd >= 0 and metrics.spend_usd >= metrics.budget_usd:
        return StopLossDecision(False, "research budget exhausted")
    if metrics.projected_net_usd < 0:
        return StopLossDecision(False, "projected net value is negative")
    if metrics.consecutive_empty_rounds >= 3 and metrics.evidence_gain < 0.1:
        return StopLossDecision(False, "three low-information rounds without meaningful evidence gain")
    if (
        metrics.duplicate_probability >= 0.9
        and metrics.novelty_score < 0.25
        and metrics.evidence_gain < 0.25
    ):
        return StopLossDecision(False, "duplicate probability is high and novelty is low")
    return StopLossDecision(True, "research remains economically justified")


class StopLossAgent:
    """Cut dead-end research before it consumes more model/scanner/human budget."""

    role = AgentRole.PROFITABILITY

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]:
        item = context.memory.get("profit:run_metrics")
        if item is None or not isinstance(item.value, list):
            return ()
        proposals: list[AgentProposal] = []
        for index, metrics in enumerate(item.value):
            if not isinstance(metrics, ResearchRunMetrics):
                continue
            decision = evaluate_stop_loss(metrics)
            proposals.append(
                AgentProposal(
                    role=self.role,
                    action="continue_research" if decision.continue_research else "stop_research_branch",
                    rationale=decision.reason,
                    risk=RiskClass.OFFLINE,
                    expected_information_gain=max(0.0, min(1.0, metrics.evidence_gain)),
                    metadata={
                        "run_index": index,
                        "projected_net_usd": metrics.projected_net_usd,
                        "spend_usd": metrics.spend_usd,
                        "continue": decision.continue_research,
                    },
                )
            )
        return tuple(proposals)
