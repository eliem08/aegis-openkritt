from decimal import Decimal

from aegis.ai.agentic_os import SecurityKnowledgeGraph
from aegis.ai.jarvis.exploit_chain_intelligence import (
    CoverageStateCell,
    EvidenceCapability,
    ExploitChainAgentV2,
    TechniqueEconomicModel,
    TechniqueOutcome,
    TechniqueResolution,
    select_state_cells,
)
from aegis.ai.jarvis.hunter_phase_h import HunterIntelligencePhaseH
from aegis.ai.jarvis.mission_scheduler import TaskState
from aegis.ingest.program import ProgramRules


def _capabilities(*, authorized=True, payout=Decimal("5000")):
    return (
        EvidenceCapability(
            "ssrf", "ssrf_url_consumer", ("url_input",), ("internal_read",), 0.9,
            Decimal("10"), None, ("evidence:ssrf",), authorized,
        ),
        EvidenceCapability(
            "credential", "cloud_credential_use", ("internal_read",),
            ("cloud_identity",), 0.8, Decimal("20"), payout,
            ("evidence:credential",), authorized,
        ),
        EvidenceCapability(
            "admin", "cloud_authz", ("cloud_identity",), ("admin_access",), 0.7,
            Decimal("30"), payout, ("evidence:admin",), authorized,
        ),
    )


def test_chain_agent_matches_preconditions_outputs_and_calculates_ev():
    chains = ExploitChainAgentV2().build(
        _capabilities(), initial_capabilities=("url_input",), max_depth=4
    )
    chain = next(row for row in chains if len(row.steps) == 3)
    assert [row.capability_id for row in chain.steps] == ["ssrf", "credential", "admin"]
    assert "admin_access" in chain.final_capabilities
    assert chain.confidence == 0.9 * 0.8 * 0.7
    assert chain.expected_payout_usd == Decimal("5000")
    assert chain.expected_net_usd == Decimal("5000") * Decimal(str(chain.confidence)) - Decimal("60")


def test_chain_agent_preserves_unknown_payout_and_scope_prerequisite():
    chains = ExploitChainAgentV2().build(
        _capabilities(authorized=False, payout=None), initial_capabilities=("url_input",)
    )
    chain = next(row for row in chains if len(row.steps) == 3)
    assert chain.expected_payout_usd is None
    assert chain.expected_net_usd is None
    assert chain.prerequisite_state == "scope_confirmation_required"


def test_chain_agent_does_not_chain_unmatched_or_outputless_steps():
    rows = (
        EvidenceCapability("a", "a", ("missing",), ("x",), 1.0, authorized=True),
        EvidenceCapability("b", "b", ("x",), ("x",), 1.0, authorized=True),
    )
    assert ExploitChainAgentV2().build(rows, initial_capabilities=("seed",)) == ()


def test_technique_economics_distinguishes_na_duplicate_rejected_and_nullable_payout():
    outcomes = (
        TechniqueOutcome("ssrf_url_consumer", TechniqueResolution.ACCEPTED, Decimal("4000")),
        TechniqueOutcome("ssrf_url_consumer", TechniqueResolution.DUPLICATE),
        TechniqueOutcome("ssrf_url_consumer", TechniqueResolution.REJECTED),
        TechniqueOutcome("ssrf_url_consumer", TechniqueResolution.NOT_APPLICABLE),
    )
    prior = TechniqueEconomicModel().learn(outcomes)[0]
    assert prior.samples == 4
    assert prior.applicable_samples == 3
    assert prior.mean_payout_usd == Decimal("4000")
    unknown = TechniqueEconomicModel().learn((
        TechniqueOutcome("race", TechniqueResolution.REJECTED),
    ))[0]
    assert unknown.mean_payout_usd is None


def test_coverage_state_selection_prefers_unseen_changed_value_without_cartesian_generation():
    rows = (
        CoverageStateCell("seen", "paid", "refund", "owner", 3, 1000),
        CoverageStateCell("new", "cancelled", "refund", "owner", 0, 500),
        CoverageStateCell("changed", "pending", "cancel", "admin", 0, 300, True),
        CoverageStateCell("blocked", "x", "y", "z", 0, 9999,
                          prerequisite_state="scope_confirmation_required"),
    )
    selected = select_state_cells(rows, limit=2)
    assert {row.cell_id for row in selected} == {"new", "changed"}


def test_phase_h_compiles_chains_and_coverage_cells_into_canonical_missions():
    graph = SecurityKnowledgeGraph()
    result = HunterIntelligencePhaseH().run(
        program=ProgramRules(handle="chain-lab"), scope_digest="scope:chain",
        authorization_id="auth:chain", asset_locator="https://api.example.test",
        asset_authorized=True, graph=graph, capabilities=_capabilities(),
        initial_capabilities=("url_input",),
        technique_outcomes=(TechniqueOutcome(
            "exploit_capability_chain", TechniqueResolution.ACCEPTED, Decimal("6000")
        ),),
        state_cells=(CoverageStateCell(
            "cell:cancelled-refund", "cancelled", "refund", "owner", 0, 1500
        ),), capacity=20, exploration_fraction=1.0,
    )
    assert result.chains and result.selected_state_cells
    chain_opportunity = next(row for row in result.opportunities
                             if row.metadata["technique"] == "exploit_capability_chain")
    assert chain_opportunity.estimated_payout_usd is not None
    mission = next(row for row in result.missions
                   if row.opportunity_id == chain_opportunity.opportunity_id)
    assert mission.tasks[0].executor_capability == (
        "jarvis:research:exploit-capability-chain"
    )
    assert mission.tasks[0].state is TaskState.PENDING
    assert graph.nodes[chain_opportunity.opportunity_id]["kind"] == "hunt_opportunity"


def test_phase_h_inferred_chain_never_becomes_authorized():
    result = HunterIntelligencePhaseH().run(
        program=ProgramRules(handle="chain-lab"), scope_digest="scope:chain",
        authorization_id="auth:chain", asset_locator="https://inferred.invalid",
        asset_authorized=False, graph=SecurityKnowledgeGraph(),
        capabilities=_capabilities(authorized=False), initial_capabilities=("url_input",),
        capacity=20, exploration_fraction=1.0,
    )
    assert result.opportunities
    assert all(row.prerequisite_state == "scope_confirmation_required"
               for row in result.opportunities)
    assert all(task.state is TaskState.WAITING_FOR_PREREQUISITE
               for mission in result.missions for task in mission.tasks)
