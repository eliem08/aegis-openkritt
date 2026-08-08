"""Planner-ticket-verified kernel-networkless execution for ordinary local scanners.

This is the hardened production path for local-only scanner binaries that need no semantic
sandbox/mobile runtime. It verifies the execution ticket, rejects special runtime requirements,
then delegates to Bubblewrap's unshared-network backend.
"""

from __future__ import annotations

from ..tool_runtime import ToolPin, ToolRuntimeManager
from .asset_cli_executor import LocalCliExecution
from .asset_deep_capabilities import PlannedMethod
from .asset_execution_ticket import (
    AssetExecutionTicket,
    AssetExecutionTicketError,
    verify_offline_execution_ticket,
)
from .networkless_cli import NetworklessCliError, ProcessRunner, execute_networkless_cli_method


class TicketedNetworklessError(RuntimeError):
    pass


_UNSUPPORTED_RUNTIME_REQUIREMENTS = {
    "isolated_sandbox",
    "authorized_mobile_runtime",
    "authorized_cluster_access",
    "authorized_registry_access",
    "authorized_authenticated_session",
}


def _execution_kwargs(method: PlannedMethod, kwargs: dict) -> dict:
    """Bind semantic artifact inputs to scanner argv placeholders without weakening locality.

    Capability tickets intentionally describe local inputs semantically (for example an
    ``authorized_artifact``), while a number of scanner CLIs call that same local path a
    ``target`` in their argv contract.  The low-level executor quite correctly treats
    ``artifact_path`` and ``target_path`` as distinct placeholders, so normalize that naming
    mismatch here, after ticket verification and before execution.

    This is only an alias of the *same already-authorized local path*; it never invents a target,
    widens scope, or permits a network destination.
    """
    execution = dict(kwargs)
    template = tuple(getattr(method, "command_template", ()) or ())
    uses_target = any("{target}" in str(token) for token in template)
    if (
        uses_target
        and execution.get("target_path") is None
        and execution.get("artifact_path") is not None
    ):
        execution["target_path"] = execution["artifact_path"]
    return execution


def execute_ticketed_networkless_method(
    method: PlannedMethod,
    *,
    ticket: AssetExecutionTicket,
    scope_digest: str,
    runtime_manager: ToolRuntimeManager | None = None,
    pins: dict[str, ToolPin] | None = None,
    process_runner: ProcessRunner | None = None,
    **kwargs,
) -> LocalCliExecution:
    """Execute one ordinary offline scanner only after ticket + backend checks."""
    try:
        verify_offline_execution_ticket(ticket, method, scope_digest=scope_digest)
    except AssetExecutionTicketError as exc:
        raise TicketedNetworklessError(str(exc)) from exc
    unsupported = _UNSUPPORTED_RUNTIME_REQUIREMENTS.intersection(ticket.requirements)
    if unsupported:
        raise TicketedNetworklessError(
            "networkless CLI backend cannot satisfy runtime requirement(s): "
            + ", ".join(sorted(unsupported))
        )
    try:
        return execute_networkless_cli_method(
            method,
            runtime_manager=runtime_manager,
            pins=pins,
            process_runner=process_runner,
            **_execution_kwargs(method, kwargs),
        )
    except NetworklessCliError as exc:
        raise TicketedNetworklessError(str(exc)) from exc


__all__ = ["TicketedNetworklessError", "execute_ticketed_networkless_method"]
