from aegis.knowledge import KnowledgeAwarePlanner
from aegis.model import EngagementInputs, PlannedAction
from aegis.orchestrator import StaticPlanner

INPUTS = EngagementInputs(targets=["api.acme.test"])


def _actions():
    return [
        PlannedAction(target="api.acme.test", action="passive_discovery", worker="passive_recon"),
        PlannedAction(target="api.acme.test", action="safe_state_change", worker="probe"),  # CSRF, rare here
        PlannedAction(target="api.acme.test", action="authenticated_testing", worker="probe"),  # IDOR, common
    ]


def test_recon_stays_first_and_probes_reorder_by_history(insights):
    base = StaticPlanner(_actions())
    planner = KnowledgeAwarePlanner(base, insights, asset_type="url")
    plan = planner.plan(INPUTS, None)

    order = [a.action for a in plan.actions]
    assert order[0] == "passive_discovery"  # recon first
    # authenticated_testing (IDOR/access-control, common in corpus) ranks above safe_state_change (CSRF, absent)
    assert order.index("authenticated_testing") < order.index("safe_state_change")


def test_rationale_annotated_with_history_score(insights):
    base = StaticPlanner(_actions())
    plan = KnowledgeAwarePlanner(base, insights, asset_type="url").plan(INPUTS, None)
    probe = next(a for a in plan.actions if a.action == "authenticated_testing")
    assert "history score=" in probe.rationale


def test_planner_stable_with_empty_corpus():
    from aegis.knowledge import CorpusInsights, ReportCorpus

    base = StaticPlanner(_actions())
    plan = KnowledgeAwarePlanner(base, CorpusInsights(ReportCorpus()), asset_type="url").plan(INPUTS, None)
    # still returns all actions, recon first
    assert len(plan.actions) == 3
    assert plan.actions[0].action == "passive_discovery"
