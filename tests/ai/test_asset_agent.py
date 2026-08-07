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
from aegis.ai.jarvis.asset_capabilities import AssetKind


def _context(
    *,
    network: bool = False,
    state_change: bool = False,
    human: bool = False,
) -> AgentContext:
    authorization = AuthorizationEnvelope(
        scope_digest="scope-assets",
        network_allowed=network,
        state_change_allowed=state_change,
        human_approval=human,
        budget=Budget(max_cost_usd=50.0, max_requests=500, max_human_minutes=120.0),
    )
    return AgentContext(authorization, SharedMemory(), SecurityKnowledgeGraph())


def _tool_decisions(context: AgentContext, tool: str):
    planning = build_jarvis().planning_round(context)
    return [
        (proposal, decision)
        for proposal, decision in planning
        if proposal.metadata.get("tool") == tool
    ]


def test_cloud_scanner_requires_both_credentials_and_network_authorization() -> None:
    context = _context()
    context.memory.put(MemoryItem("asset:kind", AssetKind.AWS_ACCOUNT))
    context.memory.put(MemoryItem("asset:credentials_available", True))

    prowler = _tool_decisions(context, "Prowler")
    assert prowler
    assert not prowler[0][1].approved

    authorized = _context(network=True)
    authorized.memory.put(MemoryItem("asset:kind", AssetKind.AWS_ACCOUNT))
    authorized.memory.put(MemoryItem("asset:credentials_available", True))
    prowler = _tool_decisions(authorized, "Prowler")
    assert prowler[0][1].approved


def test_nuclei_is_selected_but_requires_controlled_state_change_approval() -> None:
    context = _context(network=True)
    context.memory.put(MemoryItem("asset:kind", AssetKind.DOMAIN))

    nuclei = _tool_decisions(context, "nuclei")
    assert nuclei
    assert not nuclei[0][1].approved

    authorized = _context(network=True, state_change=True, human=True)
    authorized.memory.put(MemoryItem("asset:kind", AssetKind.DOMAIN))
    nuclei = _tool_decisions(authorized, "nuclei")
    assert nuclei[0][1].approved


def test_ai_endpoint_red_team_requires_network_and_human_state_approval() -> None:
    context = _context(network=True)
    context.memory.put(MemoryItem("asset:kind", AssetKind.AI_MODEL))
    context.memory.put(MemoryItem("asset:endpoint_available", True))

    for tool in ("garak", "promptfoo"):
        decisions = _tool_decisions(context, tool)
        assert decisions
        assert not decisions[0][1].approved

    authorized = _context(network=True, state_change=True, human=True)
    authorized.memory.put(MemoryItem("asset:kind", AssetKind.AI_MODEL))
    authorized.memory.put(MemoryItem("asset:endpoint_available", True))
    for tool in ("garak", "promptfoo"):
        decisions = _tool_decisions(authorized, tool)
        assert decisions[0][1].approved


def test_store_metadata_can_run_without_binary_but_binary_scanners_remain_blocked() -> None:
    context = _context(network=True)
    context.memory.put(MemoryItem("asset:kind", AssetKind.IOS_APP_STORE))

    metadata = _tool_decisions(context, "aegis-store-metadata")
    assert metadata and metadata[0][1].approved
    assert not _tool_decisions(context, "MobSF")

    context.memory.put(MemoryItem("asset:artifact_available", True))
    mobsf = _tool_decisions(context, "MobSF")
    assert mobsf and mobsf[0][1].approved
