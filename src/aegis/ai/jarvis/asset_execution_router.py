"""Single fail-closed execution router for offline asset analysis.

The heterogeneous planner may describe network, state-changing, internal-service, local CLI and
sandbox-required methods. This router handles only planner-authorized offline methods and requires
an execution ticket recomputed from the authoritative capability planner before dispatch.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..mobsf_adapter import MobSFConfig
from ..tool_runtime import ToolPin, ToolRuntimeManager
from .asset_cli_executor import (
    CliProcessResult,
    LocalCliExecution,
    Runner,
    execute_local_cli_method,
)
from .asset_deep_capabilities import PlannedMethod
from .asset_execution_ticket import (
    AssetExecutionTicket,
    AssetExecutionTicketError,
    verify_offline_execution_ticket,
)
from .asset_executor import InternalAssetExecution, execute_internal_asset_method
from .asset_normalizers import AssetExecutionObservation, normalize_local_cli_execution
from .ghidra_sandbox import (
    GhidraSandboxExecution,
    SandboxRunner,
    execute_ghidra_sandboxed,
)


class AssetExecutionRouteError(RuntimeError):
    """Method cannot be executed by the autonomous offline route."""


@dataclass(frozen=True)
class OfflineAssetExecutionOutcome:
    tool: str
    method: str
    candidates: tuple[dict, ...]
    observations: tuple[AssetExecutionObservation, ...]
    provenance: dict[str, Any]
    local_cli: LocalCliExecution | None = None
    internal: InternalAssetExecution | None = None
    ghidra: GhidraSandboxExecution | None = None


def _internal_supported(method: PlannedMethod) -> bool:
    return (str(method.tool), str(method.method)) == ("MobSF", "rest-static-analysis")


def _ghidra_supported(method: PlannedMethod) -> bool:
    return (str(method.tool), str(method.method)) == ("Ghidra", "headless-binary-analysis")


def execute_offline_asset_method(
    method: PlannedMethod,
    *,
    ticket: AssetExecutionTicket,
    scope_digest: str,
    artifact_path: str | Path | None = None,
    target_path: str | Path | None = None,
    firmware_path: str | Path | None = None,
    source_path: str | Path | None = None,
    workspace_root: str | Path | None = None,
    retain_workspace: bool = False,
    timeout: float = 300.0,
    runtime_manager: ToolRuntimeManager | None = None,
    pins: dict[str, ToolPin] | None = None,
    runner: Runner | None = None,
    ghidra_runner: SandboxRunner | None = None,
    mobsf_config: MobSFConfig | None = None,
    mobsf_client=None,
) -> OfflineAssetExecutionOutcome:
    """Execute one method only with an intact planner-issued ticket for this scope."""
    try:
        verify_offline_execution_ticket(ticket, method, scope_digest=scope_digest)
    except AssetExecutionTicketError as exc:
        raise AssetExecutionRouteError(str(exc)) from exc

    if bool(getattr(method, "requires_network", False)):
        raise AssetExecutionRouteError(
            "network-capable asset method requires the policy-controlled dynamic executor"
        )
    if bool(getattr(method, "state_change_possible", False)):
        raise AssetExecutionRouteError(
            "state-changing asset method requires explicit approval and dynamic executor"
        )

    if _internal_supported(method):
        internal = execute_internal_asset_method(
            method,
            artifact_path=artifact_path,
            mobsf_config=mobsf_config,
            mobsf_client=mobsf_client,
        )
        observation = AssetExecutionObservation(
            kind="internal_scanner_run",
            tool=internal.tool,
            method=internal.method,
            data={
                "candidate_count": len(internal.candidates),
                "verification_state": "candidate",
                "ticket_id": ticket.ticket_id,
                "provenance": internal.provenance,
            },
        )
        provenance = dict(internal.provenance)
        provenance["execution_ticket"] = ticket.ticket_id
        provenance["scope_digest"] = ticket.scope_digest
        return OfflineAssetExecutionOutcome(
            tool=internal.tool,
            method=internal.method,
            candidates=internal.candidates,
            observations=(observation,),
            provenance=provenance,
            internal=internal,
        )

    if _ghidra_supported(method):
        if artifact_path is None:
            raise AssetExecutionRouteError("Ghidra execution requires an authorized artifact")
        try:
            ghidra = execute_ghidra_sandboxed(
                artifact_path=artifact_path,
                ticket=ticket,
                workspace_root=workspace_root,
                retain_workspace=retain_workspace,
                timeout=max(1.0, timeout),
                runtime_manager=runtime_manager,
                pins=pins,
                runner=ghidra_runner,
            )
        except Exception as exc:
            raise AssetExecutionRouteError(f"Ghidra sandbox: {exc}") from exc
        observation = AssetExecutionObservation(
            kind="binary_analysis",
            tool="Ghidra",
            method=str(method.method),
            data={
                "returncode": ghidra.returncode,
                "timed_out": ghidra.timed_out,
                "analysis_log_sha256": ghidra.analysis_log_sha256,
                "analysis_log_size": ghidra.analysis_log_size,
                "output_files": len(ghidra.outputs),
                "sandbox": ghidra.provenance.get("sandbox"),
                "verification_state": "observation",
            },
        )
        return OfflineAssetExecutionOutcome(
            tool="Ghidra",
            method=str(method.method),
            candidates=(),
            observations=(observation,),
            provenance=ghidra.provenance,
            ghidra=ghidra,
        )

    if str(method.tool).startswith("aegis-"):
        raise AssetExecutionRouteError(
            "Aegis-internal method has no concrete offline executor registered"
        )

    if not bool(getattr(method, "local_only", False)):
        raise AssetExecutionRouteError(
            "method is neither a registered internal adapter nor a local-only CLI method"
        )

    local = execute_local_cli_method(
        method,
        artifact_path=artifact_path,
        target_path=target_path,
        firmware_path=firmware_path,
        source_path=source_path,
        workspace_root=workspace_root,
        retain_workspace=retain_workspace,
        timeout=timeout,
        runtime_manager=runtime_manager,
        pins=pins,
        runner=runner,
    )
    normalized = normalize_local_cli_execution(local)
    provenance = dict(local.provenance)
    provenance.update(
        {
            "stdout_sha256": local.stdout_sha256,
            "stderr_sha256": local.stderr_sha256,
            "output_files": len(local.outputs),
            "verification_state": "candidate",
            "execution_ticket": ticket.ticket_id,
            "scope_digest": ticket.scope_digest,
        }
    )
    return OfflineAssetExecutionOutcome(
        tool=local.tool,
        method=local.method,
        candidates=normalized.candidates,
        observations=normalized.observations,
        provenance=provenance,
        local_cli=local,
    )


__all__ = [
    "AssetExecutionRouteError",
    "OfflineAssetExecutionOutcome",
    "execute_offline_asset_method",
    "CliProcessResult",
]
