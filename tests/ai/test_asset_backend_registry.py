from __future__ import annotations

from aegis.ai.jarvis.asset_backend_registry import BackendKind, backend_for_method, inventory_backends
from aegis.ai.jarvis.asset_capabilities import AssetKind
from aegis.ai.jarvis.asset_deep_capabilities import GHIDRA, RIZIN


def _by_tool(items):
    return {item.tool: item for item in items}


def test_executable_inventory_separates_networkless_cli_from_sandbox_methods():
    inventory = inventory_backends(
        AssetKind.EXECUTABLE,
        artifact_available=True,
        sandbox_available=False,
    )
    supported = _by_tool(inventory.supported_ready)
    assert "grype" in supported
    assert supported["grype"].backend is BackendKind.NETWORKLESS_CLI
    assert supported["grype"].executable_offline is True
    blocked = _by_tool(inventory.semantic_blocked)
    assert "Ghidra" in blocked
    assert "isolated_sandbox" in blocked["Ghidra"].semantic_requirements


def test_only_ghidra_has_concrete_isolated_binary_backend_today():
    ghidra = backend_for_method(GHIDRA)
    assert ghidra.backend is BackendKind.GHIDRA_SANDBOX
    assert ghidra.executable_offline is True

    rizin = backend_for_method(RIZIN)
    assert "isolated_sandbox" in rizin.semantic_requirements
    assert rizin.backend is BackendKind.UNIMPLEMENTED
    assert rizin.executable_offline is False


def test_mobile_runtime_methods_do_not_look_production_ready_without_backend():
    inventory = inventory_backends(
        AssetKind.ANDROID_APK,
        artifact_available=True,
        mobile_runtime_available=True,
    )
    supported = _by_tool(inventory.supported_ready)
    unimplemented = _by_tool(inventory.unimplemented_ready)
    assert "MobSF" in supported
    assert supported["MobSF"].backend is BackendKind.INTERNAL_ADAPTER
    assert "Frida" in unimplemented
    assert "authorized_mobile_runtime" in unimplemented["Frida"].semantic_requirements
    assert unimplemented["Frida"].executable_offline is False


def test_firmware_extension_is_supported_but_emulation_requires_dynamic_policy():
    inventory = inventory_backends(
        AssetKind.HARDWARE,
        firmware_available=True,
        sandbox_available=True,
    )
    supported = {(item.tool, item.method): item for item in inventory.supported_ready}
    assert (
        "aegis-safe-rootfs-extract",
        "bounded-archive-extraction",
    ) in supported
    assert supported[("aegis-safe-rootfs-extract", "bounded-archive-extraction")].backend is \
        BackendKind.FIRMWARE_EXTRACTION

    policy_controlled = _by_tool(inventory.unimplemented_ready)
    assert "FirmAE" in policy_controlled or "Firmadyne" in policy_controlled
    for tool in ("FirmAE", "Firmadyne"):
        if tool in policy_controlled:
            assert policy_controlled[tool].backend is BackendKind.DYNAMIC_POLICY
            assert policy_controlled[tool].executable_offline is False
            assert "policy-controlled dynamic backend" in policy_controlled[tool].reason


def test_api_network_methods_are_classified_as_dynamic_policy_not_offline_execution():
    inventory = inventory_backends(
        AssetKind.API,
        api_spec_available=True,
        endpoint_available=True,
        auth_session_available=True,
    )
    dynamic = [
        item
        for item in (*inventory.unimplemented_ready, *inventory.semantic_blocked)
        if item.backend is BackendKind.DYNAMIC_POLICY
    ]
    assert dynamic
    assert all(item.executable_offline is False for item in dynamic)


def test_missing_artifact_stays_semantically_blocked_even_if_cli_backend_exists():
    inventory = inventory_backends(AssetKind.EXECUTABLE, artifact_available=False)
    assert not any(item.tool == "grype" for item in inventory.supported_ready)
    assert any(item.tool == "grype" for item in inventory.semantic_blocked)
