from __future__ import annotations

from pathlib import Path

from aegis.ai.agentic_os import (
    AgentContext,
    AgenticOrchestrator,
    AuthorizationEnvelope,
    Budget,
    MemoryItem,
    SecurityKnowledgeGraph,
    SharedMemory,
)
from aegis.ai.jarvis.asset_capabilities import AssetKind
from aegis.ai.jarvis.offline_asset_agent import (
    ConcreteOfflineAssetAgent,
    execute_offline_asset_proposal,
)


def _context(scope="scope:offline-agent"):
    return AgentContext(
        authorization=AuthorizationEnvelope(
            scope_digest=scope,
            budget=Budget(max_cost_usd=10, max_requests=0, max_human_minutes=5),
        ),
        memory=SharedMemory(),
        graph=SecurityKnowledgeGraph(),
    )


def test_missing_local_artifact_surfaces_prerequisite_not_acquisition():
    context = _context()
    context.memory.put(MemoryItem("asset:kind", AssetKind.ANDROID_APK.value))
    proposals = tuple(ConcreteOfflineAssetAgent().propose(context))
    assert len(proposals) == 1
    assert proposals[0].action == "surface_local_artifact_prerequisite"
    assert proposals[0].risk.value == "offline"
    assert proposals[0].metadata["missing_requirement"] == "authorized_local_artifact"


def test_remote_url_is_not_treated_as_local_artifact():
    context = _context()
    context.memory.put(MemoryItem("asset:kind", AssetKind.AI_MODEL.value))
    context.memory.put(
        MemoryItem("asset:local_artifact_path", "https://example.com/model.pkl")
    )
    proposal = tuple(ConcreteOfflineAssetAgent().propose(context))[0]
    assert proposal.action == "surface_local_artifact_prerequisite"
    assert proposal.metadata["missing_requirement"] == "existing_local_artifact"


def test_existing_ai_model_gets_policy_approved_offline_proposal_and_executes_without_modelscan(tmp_path):
    model = tmp_path / "demo.pkl"
    model.write_bytes(b"\x80\x04payload")
    context = _context()
    context.memory.put(MemoryItem("asset:kind", AssetKind.AI_MODEL.value))
    context.memory.put(MemoryItem("asset:local_artifact_path", str(model)))
    orchestrator = AgenticOrchestrator((ConcreteOfflineAssetAgent(),))
    evaluated = orchestrator.planning_round(context)
    assert len(evaluated) == 1
    proposal, decision = evaluated[0]
    assert decision.approved is True
    assert proposal.action == "run_concrete_offline_asset_research"
    assert proposal.requires_network is False
    assert proposal.risk.value == "offline"

    result = execute_offline_asset_proposal(
        proposal,
        authorization=context.authorization,
        run_modelscan=False,
    )
    assert result.asset_kind == AssetKind.AI_MODEL.value
    assert result.details["deserialized"] is False
    assert {stage.stage: stage.status for stage in result.stages}["provenance"] == "complete"


def test_scope_tampering_blocks_execution(tmp_path):
    model = tmp_path / "demo.pkl"
    model.write_bytes(b"\x80\x04payload")
    context = _context("scope:one")
    context.memory.put(MemoryItem("asset:kind", AssetKind.AI_MODEL.value))
    context.memory.put(MemoryItem("asset:local_artifact_path", str(model)))
    proposal = tuple(ConcreteOfflineAssetAgent().propose(context))[0]
    proposal.metadata["scope_digest"] = "scope:two"
    try:
        execute_offline_asset_proposal(
            proposal,
            authorization=context.authorization,
            run_modelscan=False,
        )
    except PermissionError as exc:
        assert "scope digest" in str(exc)
    else:
        raise AssertionError("scope tampering must fail closed")


def test_source_code_kind_does_not_duplicate_existing_source_hunt_lane(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("print('x')", encoding="utf-8")
    context = _context()
    context.memory.put(MemoryItem("asset:kind", AssetKind.SOURCE_CODE.value))
    context.memory.put(MemoryItem("asset:local_artifact_path", str(source)))
    assert tuple(ConcreteOfflineAssetAgent().propose(context)) == ()
