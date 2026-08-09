"""Jarvis agent that routes heterogeneous assets to real scanner methods."""

from __future__ import annotations

from typing import Iterable

from ..agentic_os import AgentContext, AgentProposal, AgentRole, RiskClass
from .asset_capabilities import AssetKind
from .asset_capability_planner import (
    CapabilityRequirement,
    method_capability_requirements,
    missing_capability_requirements,
    plan_capability_scan,
)
from .asset_deep_capabilities import ExtendedAssetKind, TargetAssetKind
from .asset_execution_ticket import (
    AssetExecutionTicketError,
    CapabilityAvailability,
    issue_offline_execution_ticket,
)


class AssetCapabilityAgent:
    """Select concrete scanner lanes without bypassing prerequisites or policy."""

    role = AgentRole.ATTACK_SURFACE

    @staticmethod
    def _flag(context: AgentContext, key: str) -> bool:
        item = context.memory.get(key)
        return bool(item.value) if item is not None else False

    @staticmethod
    def _text(context: AgentContext, key: str) -> str:
        item = context.memory.get(key)
        return str(item.value) if item is not None and item.value is not None else ""

    @staticmethod
    def _strings(context: AgentContext, key: str) -> tuple[str, ...]:
        item = context.memory.get(key)
        if item is None or item.value in (None, "", (), [], {}):
            return ()
        if isinstance(item.value, str):
            return tuple(part.strip() for part in item.value.split(",") if part.strip())
        if isinstance(item.value, (tuple, list, set, frozenset)):
            return tuple(str(value) for value in item.value)
        return (str(item.value),)

    @staticmethod
    def _kind(value: object) -> TargetAssetKind | None:
        if isinstance(value, (AssetKind, ExtendedAssetKind)):
            return value
        text = str(value)
        try:
            return AssetKind(text)
        except ValueError:
            try:
                return ExtendedAssetKind(text)
            except ValueError:
                return None

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]:
        kind_item = context.memory.get("asset:kind")
        if kind_item is None:
            return ()
        kind = self._kind(kind_item.value)
        if kind is None:
            return ()

        language_hints = self._strings(context, "repository:languages")
        platform_hint = self._text(context, "binary:platform")
        service_hints = self._strings(context, "asset:service_hints")
        flags = {
            "artifact_available": self._flag(context, "asset:artifact_available"),
            "credentials_available": self._flag(context, "asset:credentials_available"),
            "api_spec_available": self._flag(context, "asset:api_spec_available"),
            "endpoint_available": self._flag(context, "asset:endpoint_available"),
            "firmware_available": self._flag(context, "asset:firmware_available"),
            "mobile_runtime_available": self._flag(context, "asset:mobile_runtime_available"),
            "sandbox_available": self._flag(context, "asset:sandbox_available"),
            "cluster_access_available": self._flag(context, "asset:cluster_access_available"),
            "registry_access_available": self._flag(context, "asset:registry_access_available"),
            "auth_session_available": self._flag(context, "asset:auth_session_available"),
        }
        availability = CapabilityAvailability(
            **flags,
            language_hints=language_hints,
            platform_hint=platform_hint,
            service_hints=service_hints,
        )
        plan = plan_capability_scan(
            kind,
            **flags,
            language_hints=language_hints,
            platform_hint=platform_hint,
            service_hints=service_hints,
        )

        proposals: list[AgentProposal] = []
        for method in plan.ready:
            risk = RiskClass.OFFLINE
            if method.requires_network:
                risk = RiskClass.READ_ONLY
            if method.state_change_possible:
                risk = RiskClass.CONTROLLED_STATE_CHANGE

            ticket_payload = None
            ticket_error = ""
            if not method.requires_network and not method.state_change_possible:
                try:
                    ticket = issue_offline_execution_ticket(
                        asset_kind=kind,
                        method=method,
                        scope_digest=context.authorization.scope_digest,
                        availability=availability,
                    )
                    ticket_payload = ticket.as_dict()
                except AssetExecutionTicketError as exc:
                    # This should be unreachable for a planner-ready method. Surface drift in
                    # metadata instead of silently weakening the prerequisite gate.
                    ticket_error = str(exc)[:240]

            proposals.append(
                AgentProposal(
                    role=self.role,
                    action="run_asset_scanner_method",
                    rationale=f"Use {method.tool} via {method.method} for {kind.value}: {method.purpose}.",
                    risk=risk,
                    expected_information_gain=0.72,
                    expected_requests=1 if method.requires_network else 0,
                    requires_network=method.requires_network,
                    metadata={
                        "asset_kind": kind.value,
                        "tool": method.tool,
                        "method": method.method,
                        "command_template": method.command_template,
                        "requirements": tuple(
                            requirement.value for requirement in method_capability_requirements(method)
                        ),
                        "local_only": method.local_only,
                        "state_change_possible": method.state_change_possible,
                        "output": method.output,
                        "execution_ticket": ticket_payload,
                        "execution_ticket_error": ticket_error or None,
                    },
                )
            )

        if plan.blocked:
            blocked = []
            for method in plan.blocked:
                missing = missing_capability_requirements(method, **flags)
                blocked.append(
                    {
                        "tool": method.tool,
                        "method": method.method,
                        "missing_requirements": tuple(requirement.value for requirement in missing),
                    }
                )
            proposals.append(
                AgentProposal(
                    role=self.role,
                    action="surface_asset_scan_prerequisites",
                    rationale=(
                        "Deeper scanners are available but prerequisites are missing; keep them blocked "
                        "rather than attempting artifact, device, sandbox, cluster, registry, or credential bypass."
                    ),
                    risk=RiskClass.OFFLINE,
                    expected_information_gain=0.15,
                    metadata={"asset_kind": kind.value, "blocked": tuple(blocked)},
                )
            )
        return tuple(proposals)


def required_prerequisites(asset_kind: TargetAssetKind) -> tuple[CapabilityRequirement, ...]:
    plan = plan_capability_scan(asset_kind)
    requirements = {
        requirement
        for method in plan.blocked
        for requirement in method_capability_requirements(method)
    }
    return tuple(sorted(requirements, key=lambda item: item.value))
