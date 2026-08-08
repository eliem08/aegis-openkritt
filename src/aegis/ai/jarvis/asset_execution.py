"""Canonical façade for autonomous offline asset execution.

A semantic execution ticket proves prerequisites were declared available; it does *not* prove
that Aegis has a concrete backend implementing those prerequisites. This façade closes that gap:
requirements such as ``isolated_sandbox`` or ``authorized_mobile_runtime`` are accepted only for
explicitly registered backends. Everything else fails closed before generic execution.

New callers should import this module rather than calling ``asset_execution_router`` directly.
"""

from __future__ import annotations

from .asset_deep_capabilities import PlannedMethod
from .asset_execution_router import (
    AssetExecutionRouteError,
    OfflineAssetExecutionOutcome,
    execute_offline_asset_method,
)
from .asset_execution_ticket import AssetExecutionTicket


class AssetExecutionBackendError(RuntimeError):
    pass


# Concrete execution backends that materially implement special runtime requirements today.
_REQUIREMENT_BACKENDS = {
    "isolated_sandbox": {
        ("Ghidra", "headless-binary-analysis"),
    },
    # Static MobSF does not require a mobile runtime; Frida/Objection are deliberately absent.
    "authorized_mobile_runtime": set(),
}


def _require_backend(ticket: AssetExecutionTicket, method: PlannedMethod) -> None:
    identity = (str(method.tool), str(method.method))
    for requirement, backends in _REQUIREMENT_BACKENDS.items():
        if requirement not in ticket.requirements:
            continue
        if identity not in backends:
            raise AssetExecutionBackendError(
                f"no concrete {requirement} backend is registered for {identity[0]}/{identity[1]}"
            )


def execute_authorized_offline_method(
    method: PlannedMethod,
    *,
    ticket: AssetExecutionTicket,
    scope_digest: str,
    **kwargs,
) -> OfflineAssetExecutionOutcome:
    """Execute only when every non-trivial semantic requirement has a concrete backend."""
    _require_backend(ticket, method)
    try:
        return execute_offline_asset_method(
            method,
            ticket=ticket,
            scope_digest=scope_digest,
            **kwargs,
        )
    except AssetExecutionRouteError:
        raise
    except Exception as exc:
        raise AssetExecutionBackendError(
            f"offline asset execution failed: {type(exc).__name__}"
        ) from exc


__all__ = [
    "AssetExecutionBackendError",
    "AssetExecutionRouteError",
    "OfflineAssetExecutionOutcome",
    "execute_authorized_offline_method",
]
