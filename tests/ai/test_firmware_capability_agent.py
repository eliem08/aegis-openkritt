from __future__ import annotations

from aegis.ai.agentic_os import (
    AgentContext,
    AuthorizationEnvelope,
    Budget,
    MemoryItem,
    SecurityKnowledgeGraph,
    SharedMemory,
)
from aegis.ai.jarvis.asset_capabilities import AssetKind
from aegis.ai.jarvis.firmware_capability_agent import FirmwareCapabilityExtensionAgent


def _context() -> AgentContext:
    return AgentContext(
        authorization=AuthorizationEnvelope(
            scope_digest="scope:firmware-agent",
            budget=Budget(max_cost_usd=10, max_requests=0, max_human_minutes=5),
        ),
        memory=SharedMemory(),
        graph=SecurityKnowledgeGraph(),
    )


def test_non_hardware_assets_get_no_firmware_extension_proposals():
    context = _context()
    context.memory.put(MemoryItem("asset:kind", AssetKind.EXECUTABLE.value))
    assert tuple(FirmwareCapabilityExtensionAgent().propose(context)) == ()


def test_hardware_without_firmware_surfaces_prerequisite_only():
    context = _context()
    context.memory.put(MemoryItem("asset:kind", AssetKind.HARDWARE.value))
    proposals = tuple(FirmwareCapabilityExtensionAgent().propose(context))
    assert len(proposals) == 1
    proposal = proposals[0]
    assert proposal.action == "surface_firmware_extension_prerequisites"
    assert proposal.metadata["missing_requirements"] == ("authorized_firmware",)
    assert proposal.metadata["execution_ticket"] if "execution_ticket" in proposal.metadata else None is None


def test_authorized_firmware_emits_ticketed_bounded_extraction_proposal():
    context = _context()
    context.memory.put(MemoryItem("asset:kind", AssetKind.HARDWARE.value))
    context.memory.put(MemoryItem("asset:firmware_available", True))
    proposals = tuple(FirmwareCapabilityExtensionAgent().propose(context))
    assert len(proposals) == 1
    proposal = proposals[0]
    assert proposal.action == "run_firmware_extension_method"
    assert proposal.risk.value == "offline"
    assert proposal.requires_network is False
    ticket = proposal.metadata["execution_ticket"]
    assert ticket["scope_digest"] == "scope:firmware-agent"
    assert ticket["requirements"] == ["authorized_firmware"]
    assert proposal.metadata["raw_filesystem_images_supported"] is False
