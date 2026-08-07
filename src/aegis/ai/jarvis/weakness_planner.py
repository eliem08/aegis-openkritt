"""Universal vulnerability planning and safe multi-finding chain reasoning.

The planner never executes exploits. It ranks hypotheses across all severity
levels and identifies combinations whose joint business impact justifies deeper
source review or disposable/local validation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from ..agentic_os import AgentContext, AgentProposal, AgentRole, RiskClass
from .weakness_catalog import HuntCandidate, SeverityTier, rank_candidates


@dataclass(frozen=True)
class ChainOpportunity:
    finding_ids: tuple[str, ...]
    tags: tuple[str, ...]
    combined_expected_payout_usd: float
    validation_cost_usd: float
    confidence: float
    rationale: str

    @property
    def expected_net_usd(self) -> float:
        return self.combined_expected_payout_usd * max(0.0, min(1.0, self.confidence)) - max(
            0.0, self.validation_cost_usd
        )


@dataclass(frozen=True)
class ChainableFinding:
    finding_id: str
    severity: SeverityTier
    tags: tuple[str, ...]
    expected_payout_usd: float
    confidence: float
    validation_cost_usd: float = 0.0


_COMPATIBLE_TAGS = {
    frozenset(("privacy", "authz")),
    frozenset(("session", "authz")),
    frozenset(("workflow", "race")),
    frozenset(("ssrf", "cloud")),
    frozenset(("file", "code-execution")),
    frozenset(("parser", "authz")),
    frozenset(("cache", "privacy")),
    frozenset(("client", "session")),
}


def chain_opportunities(findings: Iterable[ChainableFinding]) -> tuple[ChainOpportunity, ...]:
    rows = list(findings)
    opportunities: list[ChainOpportunity] = []
    for index, left in enumerate(rows):
        left_tags = set(left.tags)
        for right in rows[index + 1 :]:
            right_tags = set(right.tags)
            compatible = any(pair <= (left_tags | right_tags) for pair in _COMPATIBLE_TAGS)
            shared = left_tags & right_tags
            if not compatible and not shared:
                continue
            confidence = min(left.confidence, right.confidence) * (1.0 if compatible else 0.75)
            payout = max(left.expected_payout_usd, right.expected_payout_usd)
            if compatible:
                payout *= 1.35
            cost = left.validation_cost_usd + right.validation_cost_usd
            tags = tuple(sorted(left_tags | right_tags))
            opportunities.append(
                ChainOpportunity(
                    finding_ids=tuple(sorted((left.finding_id, right.finding_id))),
                    tags=tags,
                    combined_expected_payout_usd=payout,
                    validation_cost_usd=cost,
                    confidence=confidence,
                    rationale=(
                        "Investigate whether independently observed weaknesses share a trust "
                        "boundary or invariant and therefore have greater combined impact."
                    ),
                )
            )
    return tuple(
        sorted(
            opportunities,
            key=lambda item: (item.expected_net_usd, item.confidence, item.finding_ids),
            reverse=True,
        )
    )


class UniversalHuntAgent:
    """Rank profitable hypotheses across informational through critical severity."""

    role = AgentRole.HYPOTHESIS

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]:
        item = context.memory.get("universal:hunt_candidates")
        if item is None or not isinstance(item.value, list):
            return ()
        candidates = [candidate for candidate in item.value if isinstance(candidate, HuntCandidate)]
        ranked = rank_candidates(candidates, minimum_net_usd=0.0)
        if not ranked:
            return ()
        proposals: list[AgentProposal] = []
        for candidate in ranked[:12]:
            proposals.append(
                AgentProposal(
                    role=self.role,
                    action="investigate_universal_weakness_candidate",
                    rationale=(
                        f"Investigate {candidate.family.title} on {candidate.surface}; "
                        f"severity={candidate.severity.value}, expected_net=${candidate.expected_net_usd:.2f}, "
                        f"novelty={candidate.novelty_score:.2f}, chainability={candidate.chainability:.2f}."
                    ),
                    risk=RiskClass.OFFLINE,
                    expected_information_gain=max(
                        0.05,
                        min(
                            1.0,
                            0.35 * candidate.novelty_score
                            + 0.35 * candidate.coverage_gap
                            + 0.30 * candidate.chainability,
                        ),
                    ),
                    expected_cost_usd=max(0.0, candidate.validation_cost_usd),
                    metadata={
                        "family_id": candidate.family.family_id,
                        "surface": candidate.surface,
                        "severity": candidate.severity.value,
                        "expected_net_usd": candidate.expected_net_usd,
                        "validation_mode": candidate.family.default_validation_mode,
                    },
                )
            )
        return tuple(proposals)


class ChainReasoningAgent:
    """Surface profitable combinations of individually low/medium observations."""

    role = AgentRole.BUSINESS_LOGIC

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]:
        item = context.memory.get("universal:chainable_findings")
        if item is None or not isinstance(item.value, list):
            return ()
        findings = [finding for finding in item.value if isinstance(finding, ChainableFinding)]
        chains = tuple(chain for chain in chain_opportunities(findings) if chain.expected_net_usd > 0.0)
        return tuple(
            AgentProposal(
                role=self.role,
                action="analyze_finding_chain",
                rationale=(
                    f"Evaluate whether {', '.join(chain.finding_ids)} combine into a stronger "
                    f"trust-boundary violation; expected_net=${chain.expected_net_usd:.2f}."
                ),
                risk=RiskClass.OFFLINE,
                expected_information_gain=max(0.1, min(1.0, chain.confidence)),
                expected_cost_usd=max(0.0, chain.validation_cost_usd),
                metadata={
                    "finding_ids": chain.finding_ids,
                    "tags": chain.tags,
                    "combined_expected_payout_usd": chain.combined_expected_payout_usd,
                    "expected_net_usd": chain.expected_net_usd,
                },
            )
            for chain in chains[:8]
        )
