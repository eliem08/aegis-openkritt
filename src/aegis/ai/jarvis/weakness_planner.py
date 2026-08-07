"""Universal vulnerability planning and safe multi-finding chain reasoning.

The planner never executes exploits. It ranks hypotheses across all severity
levels and identifies combinations whose joint business impact justifies deeper
source review or disposable/local validation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from ..agentic_os import AgentContext, AgentProposal, AgentRole, RiskClass
from .hunt_generator import generate_hunt_candidates, infer_surfaces
from .profit_controls import CandidateDisposition, ProgramEligibility
from .severity_portfolio import SeverityPortfolioPolicy, select_diverse_candidates
from .state_store import JarvisStateStore
from .weakness_catalog import HuntCandidate, SeverityTier


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
    frozenset(("oauth", "client")),
    frozenset(("supply-chain", "secrets")),
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

    def __init__(self, state_store: JarvisStateStore | None = None) -> None:
        self.state_store = state_store

    def _candidates_from_context(self, context: AgentContext) -> tuple[HuntCandidate, ...]:
        explicit = context.memory.get("universal:hunt_candidates")
        if explicit is not None and isinstance(explicit.value, list):
            return tuple(candidate for candidate in explicit.value if isinstance(candidate, HuntCandidate))

        paths_item = context.memory.get("repository:paths")
        if paths_item is None or not isinstance(paths_item.value, list):
            return ()
        hints_item = context.memory.get("repository:text_hints")
        program_item = context.memory.get("program:id")
        coverage_item = context.memory.get("coverage:attempts")
        paths = [str(path) for path in paths_item.value]
        hints = [str(value) for value in hints_item.value] if hints_item and isinstance(hints_item.value, list) else []
        program_id = str(program_item.value) if program_item is not None else "unknown-program"
        coverage = coverage_item.value if coverage_item and isinstance(coverage_item.value, dict) else {}
        signals = infer_surfaces(paths, hints)
        return generate_hunt_candidates(
            program_id=program_id,
            signals=signals,
            state_store=self.state_store,
            coverage_attempts=coverage,
        )

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]:
        candidates = self._candidates_from_context(context)
        if not candidates:
            return ()
        eligibility_item = context.memory.get("program:eligibility")
        eligibility = (
            eligibility_item.value
            if eligibility_item is not None and isinstance(eligibility_item.value, ProgramEligibility)
            else ProgramEligibility()
        )
        dispositions = {candidate: eligibility.disposition(candidate) for candidate in candidates}
        eligible = [
            candidate
            for candidate, disposition in dispositions.items()
            if disposition is not CandidateDisposition.IGNORE
        ]
        selected = select_diverse_candidates(
            eligible,
            SeverityPortfolioPolicy(max_items=16, minimum_net_usd=0.0),
        )
        proposals: list[AgentProposal] = []
        for candidate in selected:
            disposition = dispositions[candidate]
            action = (
                "investigate_universal_weakness_candidate"
                if disposition is CandidateDisposition.DIRECT
                else "retain_for_chain_analysis"
            )
            proposals.append(
                AgentProposal(
                    role=self.role,
                    action=action,
                    rationale=(
                        f"Investigate {candidate.family.title} on {candidate.surface}; "
                        f"severity={candidate.severity.value}, disposition={disposition.value}, "
                        f"expected_net=${candidate.expected_net_usd:.2f}, novelty={candidate.novelty_score:.2f}, "
                        f"chainability={candidate.chainability:.2f}."
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
                    expected_cost_usd=(
                        max(0.0, candidate.validation_cost_usd)
                        if disposition is CandidateDisposition.DIRECT
                        else 0.0
                    ),
                    metadata={
                        "family_id": candidate.family.family_id,
                        "surface": candidate.surface,
                        "severity": candidate.severity.value,
                        "disposition": disposition.value,
                        "expected_net_usd": candidate.expected_net_usd,
                        "validation_mode": candidate.family.default_validation_mode,
                        "chain_tags": candidate.family.chain_tags,
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
