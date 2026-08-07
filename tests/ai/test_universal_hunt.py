from __future__ import annotations

from aegis.ai.agentic_os import (
    AgentContext,
    AuthorizationEnvelope,
    Budget,
    SecurityKnowledgeGraph,
    SharedMemory,
    MemoryItem,
)
from aegis.ai.jarvis.advanced import build_jarvis
from aegis.ai.jarvis.weakness_catalog import (
    UNIVERSAL_FAMILIES,
    HuntCandidate,
    SeverityTier,
    rank_candidates,
)
from aegis.ai.jarvis.weakness_planner import ChainableFinding, chain_opportunities


def _family(family_id: str):
    return next(family for family in UNIVERSAL_FAMILIES if family.family_id == family_id)


def _context() -> AgentContext:
    return AgentContext(
        AuthorizationEnvelope(
            scope_digest="scope-test",
            budget=Budget(max_cost_usd=100.0, max_requests=100, max_human_minutes=120.0),
        ),
        SharedMemory(),
        SecurityKnowledgeGraph(),
    )


def test_low_and_medium_candidates_are_not_filtered_by_severity() -> None:
    low = HuntCandidate(
        family=_family("privacy"),
        surface="api",
        severity=SeverityTier.LOW,
        expected_payout_usd=700.0,
        p_valid=0.9,
        p_accepted=0.9,
        p_unique=0.9,
        p_reproducible=0.95,
        validation_cost_usd=1.0,
        novelty_score=0.9,
        chainability=0.8,
        coverage_gap=1.0,
    )
    medium = HuntCandidate(
        family=_family("workflow"),
        surface="api",
        severity=SeverityTier.MEDIUM,
        expected_payout_usd=1800.0,
        p_valid=0.8,
        p_accepted=0.8,
        p_unique=0.7,
        p_reproducible=0.8,
        validation_cost_usd=4.0,
        novelty_score=0.8,
        chainability=0.7,
        coverage_gap=0.8,
    )
    high_but_bad_ev = HuntCandidate(
        family=_family("injection"),
        surface="api",
        severity=SeverityTier.HIGH,
        expected_payout_usd=2500.0,
        p_valid=0.1,
        p_accepted=0.2,
        p_unique=0.1,
        p_reproducible=0.2,
        validation_cost_usd=200.0,
        novelty_score=0.1,
        chainability=0.0,
        coverage_gap=0.1,
    )

    ranked = rank_candidates([high_but_bad_ev, low, medium])
    assert low in ranked
    assert medium in ranked
    assert high_but_bad_ev not in ranked
    assert ranked[0].expected_net_usd > 0


def test_chain_reasoning_promotes_compatible_low_medium_findings() -> None:
    privacy = ChainableFinding(
        finding_id="f-privacy",
        severity=SeverityTier.LOW,
        tags=("privacy",),
        expected_payout_usd=400.0,
        confidence=0.95,
        validation_cost_usd=1.0,
    )
    authz = ChainableFinding(
        finding_id="f-authz",
        severity=SeverityTier.MEDIUM,
        tags=("authz",),
        expected_payout_usd=1200.0,
        confidence=0.9,
        validation_cost_usd=2.0,
    )
    chains = chain_opportunities([privacy, authz])
    assert len(chains) == 1
    assert chains[0].expected_net_usd > authz.expected_payout_usd * authz.confidence - 3.0


def test_advanced_jarvis_surfaces_low_medium_profitable_work() -> None:
    context = _context()
    candidates = [
        HuntCandidate(
            family=_family("headers"),
            surface="web",
            severity=SeverityTier.LOW,
            expected_payout_usd=300.0,
            p_valid=0.95,
            p_accepted=0.85,
            p_unique=0.9,
            p_reproducible=0.95,
            validation_cost_usd=0.25,
            novelty_score=0.7,
            chainability=0.6,
            coverage_gap=1.0,
        ),
        HuntCandidate(
            family=_family("workflow"),
            surface="api",
            severity=SeverityTier.MEDIUM,
            expected_payout_usd=1500.0,
            p_valid=0.8,
            p_accepted=0.8,
            p_unique=0.75,
            p_reproducible=0.85,
            validation_cost_usd=3.0,
            novelty_score=0.85,
            chainability=0.8,
            coverage_gap=0.9,
        ),
    ]
    context.memory.put(MemoryItem("universal:hunt_candidates", candidates))
    planning = build_jarvis().planning_round(context)
    approved = [proposal for proposal, decision in planning if decision.approved]
    severities = {
        proposal.metadata.get("severity")
        for proposal in approved
        if proposal.action == "investigate_universal_weakness_candidate"
    }
    assert "low" in severities
    assert "medium" in severities
