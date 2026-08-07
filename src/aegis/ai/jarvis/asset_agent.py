"""Jarvis agent that routes heterogeneous assets to real scanner methods."""

from __future__ import annotations

from typing import Iterable

from ..agentic_os import AgentContext, AgentProposal, AgentRole, RiskClass
from .asset_capabilities import AssetKind, Requirement, plan_asset_scan


class AssetCapabilityAgent:
    """Select concrete scanner lanes without bypassing prerequisites or policy."""

    role = AgentRole.ATTACK_SURFACE

    @staticmethod
    def _flag(context: AgentContext, key: str) -> bool:
        item = context.memory.get(key)
        return bool(item.value) if item is not None else False

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]:
        kind_item = context.memory.get("asset:kind")
        if kind_item is None:
            return ()
        try:
            kind = kind_item.value if isinstance(kind_item.value, AssetKind) else AssetKind(str(kind_item.value))
        except ValueError:
            return ()

        plan = plan_asset_scan(
            kind,
            artifact_available=self._flag(context, "asset:artifact_available"),
            credentials_available=self._flag(context, "asset:credentials_available"),
            api_spec_available=self._flag(context, "asset:api_spec_available"),
            endpoint_available=self._flag(context, "asset:endpoint_available"),
            firmware_available=self._flag(context, "asset:firmware_available"),
        )
        proposals: list[AgentProposal] = []
        for method in plan.ready:
            risk = RiskClass.OFFLINE
            if method.requires_network:
                risk = RiskClass.READ_ONLY
            if method.state_change_possible:
                risk = RiskClass.CONTROLLED_STATE_CHANGE
            proposals.append(
                AgentProposal(
                    role=self.role,
                    action="run_asset_scanner_method",
                    rationale=(
                        f"Use {method.tool} via {method.method} for {kind.value}: {method.purpose}."
                    ),
                    risk=risk,
                    expected_information_gain=0.72,
                    expected_requests=1 if method.requires_network else 0,
                    requires_network=method.requires_network,
                    metadata={
                        "asset_kind": kind.value,
                        "tool": method.tool,
                        "method": method.method,
                        "command_template": method.command_template,
                        "requirement": method.requirement.value,
                        "local_only": method.local_only,
                        "state_change_possible": method.state_change_possible,
                        "output": method.output,
                    },
                )
            )

        if plan.blocked:
            proposals.append(
                AgentProposal(
                    role=self.role,
                    action="surface_asset_scan_prerequisites",
                    rationale=(
                        "Deeper scanners are available but prerequisites are missing; keep them blocked "
                        "rather than attempting acquisition or credential bypass."
                    ),
                    risk=RiskClass.OFFLINE,
                    expected_information_gain=0.15,
                    metadata={
                        "asset_kind": kind.value,
                        "blocked": tuple(
                            {
                                "tool": method.tool,
                                "method": method.method,
                                "requirement": method.requirement.value,
                            }
                            for method in plan.blocked
                        ),
                    },
                )
            )
        return tuple(proposals)


def required_prerequisites(asset_kind: AssetKind) -> tuple[Requirement, ...]:
    plan = plan_asset_scan(asset_kind)
    return tuple(sorted({method.requirement for method in plan.blocked}, key=lambda item: item.value))
