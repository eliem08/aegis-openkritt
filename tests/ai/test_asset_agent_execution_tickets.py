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
from aegis.ai.jarvis.asset_execution_ticket import AssetExecutionTicket


def _context() -> AgentContext:
    return AgentContext(
        AuthorizationEnvelope(
            scope_digest="scope:asset-ticket",
            budget=Budget(max_cost_usd=50, max_requests=10, max_human_minutes=10),
        ),
        SharedMemory(),
        SecurityKnowledgeGraph(),
    )


def _proposal(context: AgentContext, tool: str):
    for proposal, _decision in build_jarvis().planning_round(context):
        if proposal.action == "run_asset_scanner_method" and proposal.metadata.get("tool") == tool:
            return proposal
    return None


def test_artifact_scanner_proposal_contains_intact_serialized_ticket():
    context = _context()
    context.memory.put(MemoryItem("asset:kind", AssetKind.EXECUTABLE))
    context.memory.put(MemoryItem("asset:artifact_available", True))
    proposal = _proposal(context, "grype")
    assert proposal is not None
    payload = proposal.metadata["execution_ticket"]
    assert payload is not None
    ticket = AssetExecutionTicket.from_dict(payload)
    assert ticket.scope_digest == "scope:asset-ticket"
    assert ticket.tool == "grype"
    assert ticket.requirements == ("authorized_artifact",)
    assert proposal.metadata["execution_ticket_error"] is None


def test_ghidra_ticket_appears_only_after_sandbox_prerequisite_is_present():
    context = _context()
    context.memory.put(MemoryItem("asset:kind", AssetKind.EXECUTABLE))
    context.memory.put(MemoryItem("asset:artifact_available", True))
    assert _proposal(context, "Ghidra") is None

    context.memory.put(MemoryItem("asset:sandbox_available", True))
    proposal = _proposal(context, "Ghidra")
    assert proposal is not None
    ticket = AssetExecutionTicket.from_dict(proposal.metadata["execution_ticket"])
    assert set(ticket.requirements) == {"authorized_artifact", "isolated_sandbox"}
