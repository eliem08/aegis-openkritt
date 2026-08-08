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
            **kwargs,
        )
    except NetworklessCliError as exc:
        raise TicketedNetworklessError(str(exc)) from exc


__all__ = ["TicketedNetworklessError", "execute_ticketed_networkless_method"]
