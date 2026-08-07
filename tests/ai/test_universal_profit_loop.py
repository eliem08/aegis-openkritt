from __future__ import annotations

from aegis.ai.agentic_os import (
    AgentContext,
    AuthorizationEnvelope,
    Budget,
    MemoryItem,
    SecurityKnowledgeGraph,
    SharedMemory,
)
from aegis.ai.jarvis.advanced import build_jarvis
from aegis.ai.jarvis.hunt_generator import generate_hunt_candidates, infer_surfaces
from aegis.ai.jarvis.profit_controls import (
    CandidateDisposition,
    ProgramEligibility,
    ResearchRunMetrics,
    evaluate_stop_loss,
)
from aegis.ai.jarvis.state_store import JarvisStateStore
from aegis.ai.jarvis.weakness_catalog import SeverityTier


def _context() -> AgentContext:
    return AgentContext(
        AuthorizationEnvelope(
            scope_digest="scope-universal",
            budget=Budget(max_cost_usd=500.0, max_requests=100, max_human_minutes=180.0),
        ),
        SharedMemory(),
        SecurityKnowledgeGraph(),
    )


def test_surface_inference_covers_modern_attack_surfaces() -> None:
    signals = infer_surfaces(
        [
            "src/graphql/schema.py",
            "src/auth/oidc.py",
            ".github/workflows/release.yml",
            "infra/main.tf",
            "src/jobs/webhook_worker.py",
            "src/uploads/archive.py",
        ],
        ["nginx x-forwarded-host", "stripe checkout", "socket.io websocket"],
    )
    surfaces = {signal.surface for signal in signals}
    assert {"graphql", "sso", "ci", "iac", "webhooks", "uploads", "proxy", "payments", "websocket"} <= surfaces
    assert "source" in surfaces


def test_generator_keeps_info_low_medium_and_high_families() -> None:
    signals = infer_surfaces(
        ["src/api/router.py", "src/errors/debug.py", "src/web/app.py", "src/auth/oauth.py"],
        ["cache-control cors openid"],
    )
    candidates = generate_hunt_candidates(program_id="p", signals=signals)
    severities = {candidate.severity for candidate in candidates}
    assert SeverityTier.INFO in severities
    assert SeverityTier.LOW in severities
    assert SeverityTier.MEDIUM in severities
    assert SeverityTier.HIGH in severities


def test_program_policy_keeps_unpaid_low_issue_for_chaining() -> None:
    signals = infer_surfaces(["src/web/app.py"], ["cache-control cors"])
    candidates = generate_hunt_candidates(program_id="p", signals=signals)
    low = next(candidate for candidate in candidates if candidate.severity is SeverityTier.LOW and candidate.chainability > 0)
    policy = ProgramEligibility(
        paid_severities=(SeverityTier.MEDIUM, SeverityTier.HIGH, SeverityTier.CRITICAL),
        keep_unpaid_chain_evidence=True,
    )
    assert policy.disposition(low) is CandidateDisposition.CHAIN_ONLY


def test_learned_outcomes_change_generated_candidate_priors() -> None:
    with JarvisStateStore() as store:
        for _ in range(4):
            store.record_outcome(
                program_id="program-a",
                weakness="authz",
                accepted=True,
                duplicate=False,
                payout_usd=2400.0,
                cost_usd=3.0,
            )
        signals = infer_surfaces(["src/api/router.py"])
        candidates = generate_hunt_candidates(
            program_id="program-a",
            signals=signals,
            state_store=store,
        )
        authz = next(candidate for candidate in candidates if candidate.family.family_id == "authz")
        assert authz.p_accepted > 0.5
        assert authz.p_unique > 0.5
        assert authz.expected_payout_usd == 2400.0
        assert authz.validation_cost_usd == 3.0


def test_advanced_jarvis_self_starts_from_repository_paths() -> None:
    context = _context()
    context.memory.put(MemoryItem("program:id", "program-a"))
    context.memory.put(
        MemoryItem(
            "repository:paths",
            ["src/api/router.py", "src/auth/oidc.py", "src/graphql/schema.py", "src/errors/debug.py"],
        )
    )
    planning = build_jarvis().planning_round(context)
    actions = [proposal.action for proposal, decision in planning if decision.approved]
    assert "investigate_universal_weakness_candidate" in actions


def test_stop_loss_cuts_dead_end_but_not_reproduced_finding() -> None:
    dead = ResearchRunMetrics(
        projected_net_usd=50.0,
        spend_usd=10.0,
        budget_usd=100.0,
        evidence_gain=0.02,
        consecutive_empty_rounds=3,
        duplicate_probability=0.3,
        novelty_score=0.4,
    )
    assert not evaluate_stop_loss(dead).continue_research

    reproduced = ResearchRunMetrics(
        projected_net_usd=-1.0,
        spend_usd=100.0,
        budget_usd=100.0,
        evidence_gain=0.0,
        consecutive_empty_rounds=4,
        duplicate_probability=0.95,
        novelty_score=0.0,
        reproduced=True,
    )
    assert evaluate_stop_loss(reproduced).continue_research
