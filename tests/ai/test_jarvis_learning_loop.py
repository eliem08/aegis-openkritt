from __future__ import annotations

from aegis.ai.agentic_os import AgentContext, AuthorizationEnvelope, Budget, SecurityKnowledgeGraph, SharedMemory
from aegis.ai.jarvis.advanced import build_jarvis
from aegis.ai.jarvis.coverage import CoverageCell
from aegis.ai.jarvis.learning_agents import (
    BountyOutcome,
    ConfirmedFinding,
    CoverageOptimizerAgent,
    MissionSchedulerAgent,
    OutcomeLearningAgent,
    RuleSynthesisAgent,
    VulnerabilityFamilyAgent,
)
from aegis.ai.jarvis.mission_scheduler import (
    MissionScheduler,
    TaskState,
    build_linear_mission,
)
from aegis.ai.jarvis.rule_factory import to_record, validate_rule_fixture_counts
from aegis.ai.jarvis.state_store import JarvisStateStore


def _context() -> AgentContext:
    return AgentContext(
        authorization=AuthorizationEnvelope(
            scope_digest="scope-test",
            budget=Budget(max_cost_usd=100.0, max_requests=100, max_human_minutes=120.0),
        ),
        memory=SharedMemory(),
        graph=SecurityKnowledgeGraph(),
    )


def test_outcome_learning_persists_bayesian_priors(tmp_path) -> None:
    path = tmp_path / "jarvis.db"
    with JarvisStateStore(path) as store:
        priors = OutcomeLearningAgent().learn(
            store,
            (
                BountyOutcome("Program-A", "Authorization", True, False, 1200.0, 10.0),
                BountyOutcome("Program-A", "Authorization", True, False, 800.0, 10.0),
                BountyOutcome("Program-A", "Authorization", False, True, 0.0, 5.0),
            ),
        )
        assert len(priors) == 1
        assert priors[0].samples == 3
        assert priors[0].acceptance_probability > 0.5
        assert priors[0].uniqueness_probability > 0.5

    with JarvisStateStore(path) as reopened:
        prior = reopened.learned_prior("program-a", "authorization")
        assert prior.samples == 3
        assert prior.mean_payout_usd == 1000.0
        assert prior.mean_cost_usd > 0


def test_vulnerability_family_is_cross_program_and_rule_is_fixture_gated(tmp_path) -> None:
    findings = (
        ConfirmedFinding(
            "program-a",
            "finding-1",
            "authorization occurs before canonical object resolution",
            "resolved object owner must match current user",
            "CWE-639",
            ("authorization", "canonicalization"),
            0.95,
        ),
        ConfirmedFinding(
            "program-b",
            "finding-9",
            "authorization occurs before canonical object resolution",
            "resolved object owner must match current user",
            "CWE-639",
            ("authorization", "api"),
            0.9,
        ),
    )
    with JarvisStateStore(tmp_path / "families.db") as store:
        families = VulnerabilityFamilyAgent().learn(store, findings)
        assert len(families) == 1
        family = families[0]
        assert family.exemplars == ("program-a:finding-1", "program-b:finding-9")
        assert family.family_id.startswith("vf1:")

        drafts = RuleSynthesisAgent().draft(families, engines=("semgrep",))
        assert len(drafts) == 1
        weak = validate_rule_fixture_counts(
            true_positives=1,
            false_positives=0,
            false_negatives=0,
            true_negatives=1,
        )
        assert not weak.promotable
        strong = validate_rule_fixture_counts(
            true_positives=4,
            false_positives=0,
            false_negatives=1,
            true_negatives=5,
        )
        assert strong.promotable
        store.upsert_rule_candidate(to_record(drafts[0], strong))
        saved = store.rule_candidate(drafts[0].rule_id)
        assert saved is not None
        assert saved.status == "validated"
        assert saved.precision == 1.0


def test_coverage_optimizer_prefers_changed_high_value_blind_spot() -> None:
    cells = (
        CoverageCell("rest", "authorization", attempts=5, expected_value_usd=1000.0),
        CoverageCell(
            "workers",
            "authorization",
            attempts=0,
            changed_since_last_attempt=True,
            expected_value_usd=3000.0,
        ),
        CoverageCell("graphql", "xss", attempts=0, expected_value_usd=100.0),
    )
    ranked = CoverageOptimizerAgent.rank(cells)
    assert ranked[0].surface == "workers"
    assert ranked[0].weakness == "authorization"


def test_mission_checkpoint_survives_restart_and_unlocks_dependencies(tmp_path) -> None:
    path = tmp_path / "missions.db"
    with JarvisStateStore(path) as store:
        scheduler = MissionScheduler(store)
        plan = build_linear_mission(
            mission_id="mission-1",
            scope_digest="scope-1",
            objective="reproduce a high-value candidate locally",
            steps=(
                ("profile", "repository_intelligence", "profile_repository"),
                ("validate", "dataflow", "validate_source_path"),
                ("reproduce", "reproduction", "run_local_reproduction"),
            ),
        )
        scheduler.create(plan)
        assert [task.task_id for task in scheduler.ready_tasks(plan)] == ["profile"]
        plan = scheduler.set_task_state(plan, "profile", TaskState.COMPLETE)
        assert [task.task_id for task in scheduler.ready_tasks(plan)] == ["validate"]

    with JarvisStateStore(path) as reopened:
        scheduler = MissionScheduler(reopened)
        resumed = MissionSchedulerAgent.next_ready(scheduler, "mission-1")
        assert resumed is not None
        plan, ready = resumed
        assert plan.cursor == 1
        assert ready == ("validate",)


def test_advanced_council_contains_learning_agents() -> None:
    orchestrator = build_jarvis()
    names = {type(agent).__name__ for agent in orchestrator.agents}
    assert {
        "OutcomeLearningAgent",
        "VulnerabilityFamilyAgent",
        "RuleSynthesisAgent",
        "CoverageOptimizerAgent",
        "MissionSchedulerAgent",
    }.issubset(names)

    context = _context()
    assert orchestrator.planning_round(context) == []
