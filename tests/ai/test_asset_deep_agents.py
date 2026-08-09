from __future__ import annotations

from aegis.ai.agentic_os import (
    AgentContext,
    AuthorizationEnvelope,
    Budget,
    MemoryItem,
    SecurityKnowledgeGraph,
    SharedMemory,
    mint_execution_grant,
    process_grant_verifier,
)
from aegis.ai.jarvis.advanced import build_jarvis
from aegis.ai.jarvis.asset_capabilities import AssetKind
from aegis.ai.jarvis.asset_deep_capabilities import ExtendedAssetKind


def _context(*, network: bool = False, state_change: bool = False, human: bool = False) -> AgentContext:
    budget = Budget(max_cost_usd=50.0, max_requests=500, max_human_minutes=120.0)
    # elevated capability comes from a signed grant (verified by build_jarvis's policy), not a
    # boolean set on the envelope.
    grant = None
    if network or state_change or human:
        grant = mint_execution_grant(
            type("_Allowed", (), {"allowed": True})(), scope_digest="scope-deep-assets",
            budget=budget, verifier=process_grant_verifier(), network=network,
            state_change=state_change, human_approval=human)
    return AgentContext(
        AuthorizationEnvelope(
            scope_digest="scope-deep-assets",
            external_model_egress_allowed=True,
            budget=budget,
            grant=grant,
        ),
        SharedMemory(),
        SecurityKnowledgeGraph(),
    )


def _decisions(context: AgentContext, *, tool: str | None = None, action: str | None = None):
    rows = build_jarvis().planning_round(context)
    if tool is not None:
        rows = [row for row in rows if row[0].metadata.get("tool") == tool]
    if action is not None:
        rows = [row for row in rows if row[0].action == action]
    return rows


def test_mobile_runtime_tool_is_selected_but_state_change_stays_human_gated() -> None:
    context = _context()
    context.memory.put(MemoryItem("asset:kind", AssetKind.ANDROID_APK))
    context.memory.put(MemoryItem("asset:artifact_available", True))
    context.memory.put(MemoryItem("asset:mobile_runtime_available", True))

    frida = _decisions(context, tool="Frida")
    assert frida
    assert not frida[0][1].approved

    approved = _context(state_change=True, human=True)
    approved.memory.put(MemoryItem("asset:kind", AssetKind.ANDROID_APK))
    approved.memory.put(MemoryItem("asset:artifact_available", True))
    approved.memory.put(MemoryItem("asset:mobile_runtime_available", True))
    frida = _decisions(approved, tool="Frida")
    assert frida[0][1].approved


def test_kubernetes_scanner_requires_cluster_access_and_network_authorization() -> None:
    context = _context()
    context.memory.put(MemoryItem("asset:kind", ExtendedAssetKind.KUBERNETES_CLUSTER))
    context.memory.put(MemoryItem("asset:cluster_access_available", True))

    kubescape = _decisions(context, tool="Kubescape")
    assert kubescape
    assert not kubescape[0][1].approved

    approved = _context(network=True)
    approved.memory.put(MemoryItem("asset:kind", ExtendedAssetKind.KUBERNETES_CLUSTER))
    approved.memory.put(MemoryItem("asset:cluster_access_available", True))
    kubescape = _decisions(approved, tool="Kubescape")
    assert kubescape[0][1].approved


def test_ai_red_team_depth_remains_network_state_and_human_gated() -> None:
    context = _context(network=True)
    context.memory.put(MemoryItem("asset:kind", ExtendedAssetKind.LLM_RAG_APP))
    context.memory.put(MemoryItem("asset:endpoint_available", True))

    pyrit = _decisions(context, tool="PyRIT")
    assert pyrit
    assert not pyrit[0][1].approved

    approved = _context(network=True, state_change=True, human=True)
    approved.memory.put(MemoryItem("asset:kind", ExtendedAssetKind.LLM_RAG_APP))
    approved.memory.put(MemoryItem("asset:endpoint_available", True))
    pyrit = _decisions(approved, tool="PyRIT")
    assert pyrit[0][1].approved


def test_specialist_android_and_api_agents_join_the_council() -> None:
    android = _context()
    android.memory.put(MemoryItem("asset:kind", AssetKind.ANDROID_APK))
    assert _decisions(android, action="analyze_android_asset")

    graphql = _context()
    graphql.memory.put(MemoryItem("asset:kind", ExtendedAssetKind.GRAPHQL_ENDPOINT))
    assert _decisions(graphql, action="analyze_api_protocol_asset")
