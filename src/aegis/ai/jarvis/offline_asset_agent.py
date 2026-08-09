"""Canonical Jarvis agent for concrete safe-offline heterogeneous pipelines."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from ..agentic_os import (
    AgentContext,
    AgentProposal,
    AgentRole,
    AuthorizationEnvelope,
    ProposalPolicy,
    RiskClass,
)
from ..mobsf_adapter import MobSFConfig
from ..tool_runtime import ToolPin, ToolRuntimeManager
from .asset_capabilities import AssetKind
from .offline_asset_research import OfflineAssetResearchReport, run_offline_asset_research


class ConcreteOfflineAssetAgent:
    """Propose one concrete local-artifact research pipeline; never acquire artifacts."""

    role = AgentRole.ATTACK_SURFACE
    supported = frozenset(
        {
            AssetKind.ANDROID_APK,
            AssetKind.IOS_IPA,
            AssetKind.EXECUTABLE,
            AssetKind.HARDWARE,
            AssetKind.AI_MODEL,
            AssetKind.SMART_CONTRACT,
        }
    )

    @staticmethod
    def _value(context: AgentContext, key: str, default=None):
        item = context.memory.get(key)
        return item.value if item is not None else default

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]:
        raw_kind = self._value(context, "asset:kind", "")
        try:
            kind = AssetKind(str(raw_kind))
        except ValueError:
            return ()
        if kind not in self.supported:
            return ()
        raw_path = str(self._value(context, "asset:local_artifact_path", "") or "").strip()
        if not raw_path:
            return (
                AgentProposal(
                    role=self.role,
                    action="surface_local_artifact_prerequisite",
                    rationale=(
                        f"{kind.value} has a concrete offline pipeline, but no authorized local "
                        "artifact path is present. Aegis will not acquire or derive one implicitly."
                    ),
                    risk=RiskClass.OFFLINE,
                    expected_information_gain=0.05,
                    metadata={
                        "asset_kind": kind.value,
                        "missing_requirement": "authorized_local_artifact",
                    },
                ),
            )
        path = Path(raw_path).expanduser()
        local_exists = path.is_file()
        if not local_exists:
            return (
                AgentProposal(
                    role=self.role,
                    action="surface_local_artifact_prerequisite",
                    rationale=(
                        "The supplied artifact reference is not an existing local regular file; "
                        "URLs/store identifiers/endpoints are never treated as artifact bytes."
                    ),
                    risk=RiskClass.OFFLINE,
                    expected_information_gain=0.05,
                    metadata={
                        "asset_kind": kind.value,
                        "missing_requirement": "existing_local_artifact",
                    },
                ),
            )
        return (
            AgentProposal(
                role=self.role,
                action="run_concrete_offline_asset_research",
                rationale=(
                    f"Run the implemented safe-offline {kind.value} artifact pipeline under the "
                    "current scope; dynamic/network/state-changing methods remain excluded."
                ),
                risk=RiskClass.OFFLINE,
                expected_information_gain=0.85,
                metadata={
                    "asset_kind": kind.value,
                    "local_artifact_path": str(path.resolve()),
                    "scope_digest": context.authorization.scope_digest,
                    "sandbox_available": bool(
                        self._value(context, "asset:sandbox_available", False)
                    ),
                    "dynamic_runtime_used": False,
                },
            ),
        )


def execute_offline_asset_proposal(
    proposal: AgentProposal,
    *,
    authorization: AuthorizationEnvelope,
    workspace_root: str | Path | None = None,
    runtime_manager: ToolRuntimeManager | None = None,
    pins: dict[str, ToolPin] | None = None,
    process_runner=None,
    ghidra_runner=None,
    mobsf_config: MobSFConfig | None = None,
    mobsf_client=None,
    include_ghidra: bool = False,
    run_modelscan: bool = True,
) -> OfflineAssetResearchReport:
    """Policy-check and execute only the exact canonical offline proposal action."""
    if proposal.action != "run_concrete_offline_asset_research":
        raise ValueError("proposal is not a concrete offline asset research action")
    decision = ProposalPolicy().evaluate(proposal, authorization)
    if not decision.approved:
        raise PermissionError("offline asset research proposal was denied by ProposalPolicy")
    metadata = proposal.metadata or {}
    if str(metadata.get("scope_digest") or "") != authorization.scope_digest:
        raise PermissionError("proposal scope digest does not match authorization")
    return run_offline_asset_research(
        str(metadata.get("asset_kind") or ""),
        str(metadata.get("local_artifact_path") or ""),
        scope_digest=authorization.scope_digest,
        workspace_root=workspace_root,
        runtime_manager=runtime_manager,
        pins=pins,
        process_runner=process_runner,
        ghidra_runner=ghidra_runner,
        mobsf_config=mobsf_config,
        mobsf_client=mobsf_client,
        include_ghidra=include_ghidra,
        sandbox_available=bool(metadata.get("sandbox_available")),
        run_modelscan=run_modelscan,
    )


def extend_jarvis_with_offline_assets(base_orchestrator):
    """Reuse the canonical orchestrator/policy and append this concrete capability agent."""
    from ..agentic_os import AgenticOrchestrator

    return AgenticOrchestrator(
        (*base_orchestrator.agents, ConcreteOfflineAssetAgent()),
        policy=base_orchestrator.policy,
    )
