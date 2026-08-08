from __future__ import annotations

from types import SimpleNamespace

from aegis.ai.active_bridge import followup_intents_for_finding, plan_active_proposals
from aegis.ai.agentic_os import AuthorizationEnvelope, Budget, EvidenceStage, ProposalPolicy
from aegis.ai.auto_hunt import HuntTarget
from aegis.ai.jarvis.graph_store import SqliteSecurityKnowledgeGraph
from aegis.ai.jarvis.mission_scheduler import MissionScheduler
from aegis.ai.jarvis.state_store import JarvisStateStore
from aegis.ai.jarvis_bridge import evaluate_finding
from aegis.graph import Asset, AssetKind


def _row(weakness: str = "CWE-89", summary: str = "SQL injection") -> dict:
    return {
        "source": "aegis:llm",
        "agreement": 3,
        "samples": 3,
        "severity": "high",
        "validation": {"verdict": "confirmed", "confidence": 0.92},
        "reachability": {"verdict": "reachable"},
        "json_answer": {
            "vulnerability_type": weakness,
            "summary": summary,
            "file_path": "app/routes.py",
            "line": 41,
        },
    }


def _auth(allowed: bool = True):
    return SimpleNamespace(
        repository="acme/repo",
        allowed=allowed,
        status="authorized" if allowed else "blocked",
        reason="in scope" if allowed else "not in scope",
        record=SimpleNamespace(scope_snapshot_hash="scope1234"),
    )


def _target(reward: float = 5000.0) -> HuntTarget:
    return HuntTarget(
        repository="acme/repo",
        handle="acme",
        reward_ceiling=reward,
        findability=0.8,
        duplicate_risk=0.1,
    )


def test_confirmed_authorized_row_becomes_source_supported(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_JARVIS_STATE_DB", str(tmp_path / "jarvis.sqlite3"))
    row = _row()
    decision = evaluate_finding(
        row,
        _target(),
        _auth(True),
        report_root=tmp_path,
        model_egress_allowed=True,
        human_hour_cost_usd=0,
    )
    assert decision.source_decision.approved is True
    assert decision.stage is EvidenceStage.SOURCE_SUPPORTED
    assert row["jarvis"]["stage"] == "source_supported"


def test_target_authorization_denial_blocks_even_offline_source_promotion(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_JARVIS_STATE_DB", str(tmp_path / "jarvis.sqlite3"))
    row = _row()
    decision = evaluate_finding(
        row,
        _target(),
        _auth(False),
        report_root=tmp_path,
        model_egress_allowed=True,
        human_hour_cost_usd=0,
    )
    assert decision.source_decision.approved is False
    assert "target authorization denied" in decision.source_decision.reason
    assert decision.stage is EvidenceStage.CANDIDATE
    assert decision.should_escalate is False


def test_negative_ev_is_deferred_without_changing_validation_verdict(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_JARVIS_STATE_DB", str(tmp_path / "jarvis.sqlite3"))
    row = _row()
    decision = evaluate_finding(
        row,
        _target(reward=0),
        _auth(True),
        report_root=tmp_path,
        model_egress_allowed=True,
        human_hour_cost_usd=100,
    )
    assert decision.net_ev_usd < 0
    assert decision.should_escalate is False
    assert row["validation"]["verdict"] == "confirmed"
    assert all(item.approved is False for item in decision.quality_decisions)


def test_positive_ev_creates_resumable_mission_and_reasoning_graph(tmp_path, monkeypatch):
    db = tmp_path / "jarvis.sqlite3"
    monkeypatch.setenv("AEGIS_JARVIS_STATE_DB", str(db))
    row = _row()
    decision = evaluate_finding(
        row,
        _target(),
        _auth(True),
        report_root=tmp_path,
        model_egress_allowed=True,
        human_hour_cost_usd=0,
    )
    assert decision.should_escalate is True
    assert decision.mission_id

    with JarvisStateStore(db) as store:
        mission = MissionScheduler(store).resume(decision.mission_id)
        assert mission is not None
        assert [task.action for task in mission.tasks] == [
            "adversarial_source_review",
            "reproduce_in_disposable_local_lab",
            "assemble_evidence_bundle",
        ]

    with SqliteSecurityKnowledgeGraph(db) as graph:
        repository_node = "repository:acme/repo"
        assert decision.finding_id in graph.neighbors(repository_node, "HAS_FINDING")
        assert graph.neighbors(decision.finding_id, "INSTANCE_OF") == ("weakness:cwe-89",)
        assert graph.neighbors(decision.finding_id, "SUPPORTED_BY")


def test_source_ssrf_intent_is_visible_but_vetoed_by_source_envelope(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_JARVIS_STATE_DB", str(tmp_path / "jarvis.sqlite3"))
    row = _row("CWE-918", "SSRF through webhook URL fetch")
    decision = evaluate_finding(
        row,
        _target(),
        _auth(True),
        report_root=tmp_path,
        model_egress_allowed=True,
        human_hour_cost_usd=0,
    )
    assert decision.active_decisions
    assert all(item.approved is False for item in decision.active_decisions)
    assert any("network" in item.reason for item in decision.active_decisions)


def test_active_followup_intent_never_contains_an_invented_live_target():
    proposals = followup_intents_for_finding(_row("CWE-918", "SSRF via callback URL"))
    assert proposals
    proposal = proposals[0]
    assert proposal.requires_network is True
    assert proposal.metadata["execution"] == "requires_discovered_route_plan"
    assert "targets" not in proposal.metadata


def test_active_detector_plan_requires_network_state_and_human_approval():
    route = Asset(
        engagement_id="eng",
        asset_key="route:POST api.example/graphql",
        kind=AssetKind.ROUTE,
        attributes={"method": "POST", "path": "/graphql", "host": "api.example"},
    )
    plan, proposals = plan_active_proposals([route], enabled={"graphql"})
    assert plan.has("graphql")
    assert len(proposals) == 1
    proposal = proposals[0]

    policy = ProposalPolicy()
    blocked = policy.evaluate(
        proposal,
        AuthorizationEnvelope(scope_digest="s", budget=Budget(max_requests=10)),
    )
    assert blocked.approved is False

    network_only = policy.evaluate(
        proposal,
        AuthorizationEnvelope(
            scope_digest="s",
            network_allowed=True,
            budget=Budget(max_requests=10),
        ),
    )
    assert network_only.approved is False
    assert "state changes" in network_only.reason

    approved = policy.evaluate(
        proposal,
        AuthorizationEnvelope(
            scope_digest="s",
            network_allowed=True,
            state_change_allowed=True,
            human_approval=True,
            budget=Budget(max_requests=10),
        ),
    )
    assert approved.approved is True


def test_offline_contract_review_plan_stays_offline():
    plan, proposals = plan_active_proposals(
        [],
        enabled={"contract_review"},
        contracts=({"name": "Vault", "source": "contract Vault { }"},),
    )
    assert plan.has("contract_review")
    proposal = proposals[0]
    assert proposal.requires_network is False
    approved = ProposalPolicy().evaluate(
        proposal,
        AuthorizationEnvelope(scope_digest="s", budget=Budget()),
    )
    assert approved.approved is True
