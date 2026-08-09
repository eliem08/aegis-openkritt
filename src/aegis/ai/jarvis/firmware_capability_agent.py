"""Jarvis capability agent for safe firmware extensions.

The core asset planner remains authoritative for its existing registry. This agent consumes the
single extension hook in ``asset_capability_extensions`` so newly introduced bounded firmware
methods can participate in planning without duplicating capability logic.
"""

from __future__ import annotations

from typing import Iterable

from ..agentic_os import AgentContext, AgentProposal, AgentRole, RiskClass
from .asset_capabilities import AssetKind
from .asset_capability_extensions import capability_extensions
from .asset_execution_ticket import CapabilityAvailability
from .firmware_execution import issue_safe_rootfs_ticket
from .firmware_methods import SAFE_ROOTFS_EXTRACT


class FirmwareCapabilityExtensionAgent:
    """Propose bounded firmware extraction only after authorized firmware is available."""

    role = AgentRole.ATTACK_SURFACE

    @staticmethod
    def _flag(context: AgentContext, key: str) -> bool:
        item = context.memory.get(key)
        return bool(item.value) if item is not None else False

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]:
        kind_item = context.memory.get("asset:kind")
        if kind_item is None or str(kind_item.value) != AssetKind.HARDWARE.value:
            return ()
        firmware_available = self._flag(context, "asset:firmware_available")
        extensions = capability_extensions(
            AssetKind.HARDWARE,
            firmware_available=firmware_available,
        )
        proposals: list[AgentProposal] = []
        for extension in extensions:
            method = extension.method
            if extension.ready:
                ticket = issue_safe_rootfs_ticket(
                    scope_digest=context.authorization.scope_digest,
                    availability=CapabilityAvailability(
                        firmware_available=firmware_available,
                    ),
                )
                proposals.append(
                    AgentProposal(
                        role=self.role,
                        action="run_firmware_extension_method",
                        rationale=(
                            "Boundedly extract an authorized ZIP/plain-TAR firmware container "
                            "for later integrity-bound rootfs analysis."
                        ),
                        risk=RiskClass.OFFLINE,
                        expected_information_gain=0.7,
                        metadata={
                            "asset_kind": AssetKind.HARDWARE.value,
                            "tool": method.tool,
                            "method": method.method,
                            "requirements": ticket.requirements,
                            "execution_ticket": ticket.as_dict(),
                            "raw_filesystem_images_supported": False,
                        },
                    )
                )
            else:
                proposals.append(
                    AgentProposal(
                        role=self.role,
                        action="surface_firmware_extension_prerequisites",
                        rationale=(
                            "Safe rootfs extraction remains blocked until an authorized firmware "
                            "artifact exists; Aegis will not acquire or guess firmware images."
                        ),
                        risk=RiskClass.OFFLINE,
                        expected_information_gain=0.1,
                        metadata={
                            "asset_kind": AssetKind.HARDWARE.value,
                            "tool": SAFE_ROOTFS_EXTRACT.tool,
                            "method": SAFE_ROOTFS_EXTRACT.method,
                            "missing_requirements": tuple(
                                item.value for item in extension.missing_requirements
                            ),
                        },
                    )
                )
        return tuple(proposals)


def extend_jarvis_with_firmware(base_orchestrator):
    """Return the canonical orchestrator plus the firmware extension agent.

    This does not create a second framework; it reuses the existing orchestrator and policy.
    """
    from ..agentic_os import AgenticOrchestrator

    return AgenticOrchestrator(
        (*base_orchestrator.agents, FirmwareCapabilityExtensionAgent()),
        policy=base_orchestrator.policy,
    )


__all__ = ["FirmwareCapabilityExtensionAgent", "extend_jarvis_with_firmware"]
