from aegis.model import EngagementInputs, PlannedAction
from aegis.orchestrator import (
    EscalationReason,
    Orchestrator,
    ScriptedWorker,
    StaticPlanner,
    WorkerResult,
)

INPUTS = EngagementInputs(targets=["api.example.test"])


def build(engine, actions, registry, approvals=None):
    return Orchestrator(
        engine=engine,
        planner=StaticPlanner(actions),
        workers=registry,
        engagement_id="eng-1",
        escalation_contacts=["secops@example.test"],
        approvals=approvals,
    )


def reasons(blocked_action) -> set[str]:
    return {r["code"] for r in blocked_action.decision.get("reasons", [])}


def test_allow_executes_and_maps_surface(engine, registry):
    actions = [PlannedAction(target="api.example.test", action="passive_discovery", worker="passive_recon")]
    run = build(engine, actions, registry).run(INPUTS)
    assert len(run.executed_action_ids) == 1
    assert run.surface.hosts() == {"api.example.test"}
    assert run.surface.route_count == 2
    assert run.stages == ["INGEST", "PLAN", "GATE/TEST", "TRIAGE", "LEARN"]


def test_out_of_scope_blocked(engine, registry):
    actions = [PlannedAction(target="evil.com", action="passive_discovery", worker="passive_recon")]
    run = build(engine, actions, registry).run(INPUTS)
    assert run.executed_action_ids == []
    assert len(run.blocked) == 1
    assert "target_out_of_scope" in reasons(run.blocked[0])


def test_prohibited_blocked(engine, registry):
    actions = [PlannedAction(target="api.example.test", action="denial_of_service", worker="passive_recon")]
    run = build(engine, actions, registry).run(INPUTS)
    assert len(run.blocked) == 1
    assert "action_prohibited" in reasons(run.blocked[0])


def test_require_approval_escalates(engine, registry):
    registry.register(ScriptedWorker("probe", default=WorkerResult()))
    actions = [PlannedAction(target="api.example.test", action="cross_tenant_proof", worker="probe")]
    run = build(engine, actions, registry).run(INPUTS)
    assert run.executed_action_ids == []
    assert len(run.escalations) == 1
    esc = run.escalations[0]
    assert esc.reason == EscalationReason.APPROVAL_REQUIRED
    assert set(esc.required_approvals) == {"cross_tenant_proof", "tier:SENSITIVE"}


def test_pregranted_approval_allows(engine, registry, make_candidate, make_evidence):
    ev = make_evidence()
    cand = make_candidate(evidence_id=ev.evidence_id)
    registry.register(
        ScriptedWorker("probe", results={"cross_tenant_proof": WorkerResult(candidates=[cand], evidence=[ev])})
    )
    actions = [PlannedAction(target="api.example.test", action="cross_tenant_proof", worker="probe")]
    approvals = {("cross_tenant_proof", "api.example.test"): {"cross_tenant_proof", "tier:SENSITIVE"}}
    run = build(engine, actions, registry, approvals=approvals).run(INPUTS)
    assert len(run.executed_action_ids) == 1
    assert len(run.findings) == 1


def test_kill_switch_before_run_halts(engine, registry):
    engine.kill_switch.fire("operator stop")
    actions = [PlannedAction(target="api.example.test", action="passive_discovery", worker="passive_recon")]
    run = build(engine, actions, registry).run(INPUTS)
    assert run.halted is True
    assert "kill switch" in run.halt_reason
    assert run.executed_action_ids == []
    assert any(e.reason == EscalationReason.KILL_SWITCH for e in run.escalations)


def test_kill_switch_mid_run_stops_remaining(engine, registry):
    def trip(action, ctx):
        engine.kill_switch.fire("worker tripped")
        return WorkerResult()

    registry.register(ScriptedWorker("killer", handler=trip))
    actions = [
        PlannedAction(target="api.example.test", action="passive_discovery", worker="killer"),
        PlannedAction(target="api.example.test", action="passive_discovery", worker="passive_recon"),
    ]
    run = build(engine, actions, registry).run(INPUTS)
    assert run.halted is True
    assert len(run.executed_action_ids) == 1  # first ran, second halted


def test_sensitive_data_stops_path(engine, registry, make_candidate, make_evidence):
    ev = make_evidence()
    cand = make_candidate(evidence_id=ev.evidence_id)
    registry.register(
        ScriptedWorker(
            "probe",
            results={
                "authenticated_testing": WorkerResult(
                    candidates=[cand], evidence=[ev], sensitive_data_encountered=True
                )
            },
        )
    )
    actions = [PlannedAction(target="api.example.test", action="authenticated_testing", worker="probe")]
    run = build(engine, actions, registry).run(INPUTS)
    assert run.executed_action_ids == []  # path halted before collecting
    assert run.findings == []  # raw candidates not stored
    assert len(run.safety_events) == 1
    assert run.safety_events[0].kind == "SENSITIVE_DATA_ENCOUNTERED"
    assert any(e.reason == EscalationReason.SENSITIVE_DATA for e in run.escalations)


def test_missing_worker_blocked(engine, registry):
    actions = [PlannedAction(target="api.example.test", action="passive_discovery", worker="ghost")]
    run = build(engine, actions, registry).run(INPUTS)
    assert run.executed_action_ids == []
    assert len(run.blocked) == 1
    assert run.blocked[0].decision.get("error") == "no_worker_registered"


def test_rate_budget_blocks_second_action(make_engine, registry):
    engine = make_engine(rate_limits={"requests_per_second": 1, "max_concurrent_sessions": 3})
    actions = [
        PlannedAction(target="api.example.test", action="passive_discovery", worker="passive_recon"),
        PlannedAction(target="api.example.test", action="passive_discovery", worker="passive_recon"),
    ]
    run = build(engine, actions, registry).run(INPUTS)
    assert len(run.executed_action_ids) == 1
    assert len(run.blocked) == 1
    assert "rate_budget_exceeded" in reasons(run.blocked[0])
