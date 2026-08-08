from __future__ import annotations

import pytest

from aegis.ai.jarvis.asset_deep_capabilities import DeepScannerMethod
from aegis.ai.jarvis.asset_execution import (
    AssetExecutionBackendError,
    execute_authorized_offline_method,
)
from aegis.ai.jarvis.asset_execution_ticket import AssetExecutionTicket


def _ticket(method, *requirements):
    # Integrity is intentionally irrelevant in these tests because backend enforcement must
    # happen before the lower router/verifier is reached.
    return AssetExecutionTicket(
        ticket_id="asset-ticket:v1:" + "0" * 64,
        scope_digest="scope:test",
        asset_kind="executable",
        tool=str(method.tool),
        method=str(method.method),
        requirements=tuple(requirements),
        availability_digest="1" * 64,
        offline_only=True,
    )


def test_generic_host_execution_cannot_satisfy_isolated_sandbox_requirement():
    rizin = DeepScannerMethod(
        "Rizin",
        "binary-analysis",
        ("rizin", "-A", "{artifact}"),
        local_only=True,
    )
    with pytest.raises(AssetExecutionBackendError, match="isolated_sandbox"):
        execute_authorized_offline_method(
            rizin,
            ticket=_ticket(rizin, "authorized_artifact", "isolated_sandbox"),
            scope_digest="scope:test",
            artifact_path="/does/not/matter",
        )


def test_generic_host_execution_cannot_satisfy_mobile_runtime_requirement():
    frida = DeepScannerMethod(
        "Frida",
        "runtime-instrumentation",
        ("frida", "-f", "{artifact}"),
        local_only=True,
    )
    with pytest.raises(AssetExecutionBackendError, match="authorized_mobile_runtime"):
        execute_authorized_offline_method(
            frida,
            ticket=_ticket(frida, "authorized_artifact", "authorized_mobile_runtime"),
            scope_digest="scope:test",
            artifact_path="/does/not/matter",
        )
