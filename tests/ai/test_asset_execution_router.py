from __future__ import annotations

import json

import httpx
import pytest

from aegis.ai.jarvis.asset_capabilities import GRYPE, MOBSF, SYFT, AssetKind
from aegis.ai.jarvis.asset_cli_executor import CliProcessResult
from aegis.ai.jarvis.asset_deep_capabilities import GHIDRA, DeepScannerMethod
from aegis.ai.jarvis.asset_execution_router import (
    AssetExecutionRouteError,
    execute_offline_asset_method,
)
from aegis.ai.jarvis.asset_execution_ticket import (
    AssetExecutionTicketError,
    CapabilityAvailability,
    issue_offline_execution_ticket,
)
from aegis.ai.jarvis.ghidra_sandbox import GhidraSandboxProcessResult
from aegis.ai.mobsf_adapter import MobSFConfig
from aegis.ai.tool_runtime import ToolRuntimeManager

_SCOPE = "scope:test"


def _artifact_ticket(method, asset_kind=AssetKind.EXECUTABLE):
    return issue_offline_execution_ticket(
        asset_kind=asset_kind,
        method=method,
        scope_digest=_SCOPE,
        availability=CapabilityAvailability(artifact_available=True),
    )


def test_router_executes_ready_local_cli_and_normalizes_candidates(tmp_path):
    binary = tmp_path / "grype"
    binary.write_bytes(b"grype")
    artifact = tmp_path / "rootfs.tar"
    artifact.write_bytes(b"authorized")
    manager = ToolRuntimeManager(
        resolver=lambda name: str(binary) if name == "grype" else None,
        runner=lambda argv, timeout: (0, "grype 1.0", ""),
    )
    payload = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2099-1",
                    "severity": "High",
                    "description": "demo",
                },
                "artifact": {
                    "name": "demo",
                    "version": "1",
                    "locations": [{"path": "/demo"}],
                },
            }
        ]
    }

    def runner(argv, workspace, timeout, env, maximum_output_bytes):
        return CliProcessResult(0, json.dumps(payload).encode(), b"")

    ticket = _artifact_ticket(GRYPE)
    outcome = execute_offline_asset_method(
        GRYPE,
        ticket=ticket,
        scope_digest=_SCOPE,
        artifact_path=artifact,
        runtime_manager=manager,
        pins={},
        runner=runner,
    )
    assert len(outcome.candidates) == 1
    assert outcome.candidates[0]["validation_status"] == "unverified"
    assert outcome.provenance["verification_state"] == "candidate"
    assert outcome.provenance["execution_ticket"] == ticket.ticket_id
    assert outcome.local_cli is not None
    assert outcome.internal is None
    assert outcome.ghidra is None


def test_router_executes_only_registered_internal_mobsf_method(tmp_path):
    artifact = tmp_path / "demo.apk"
    artifact.write_bytes(b"authorized")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/upload":
            return httpx.Response(200, json={"hash": "d" * 32, "scan_type": "apk"})
        if request.url.path == "/api/v1/scan":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/api/v1/report_json":
            return httpx.Response(200, json={"code_analysis": {}})
        if request.url.path == "/api/v1/delete_scan":
            return httpx.Response(200, json={"deleted": "yes"})
        raise AssertionError(request.url.path)

    client = httpx.Client(
        base_url="http://127.0.0.1:8000",
        transport=httpx.MockTransport(handler),
    )
    ticket = _artifact_ticket(MOBSF, AssetKind.ANDROID_APK)
    try:
        outcome = execute_offline_asset_method(
            MOBSF,
            ticket=ticket,
            scope_digest=_SCOPE,
            artifact_path=artifact,
            mobsf_config=MobSFConfig(api_key="key"),
            mobsf_client=client,
        )
    finally:
        client.close()
    assert outcome.internal is not None
    assert outcome.local_cli is None
    assert outcome.ghidra is None
    assert outcome.observations[0].kind == "internal_scanner_run"
    assert outcome.provenance["execution_ticket"] == ticket.ticket_id


def test_router_routes_ghidra_only_through_bubblewrap_sandbox(tmp_path):
    root = tmp_path / "ghidra"
    launcher = root / "support" / "analyzeHeadless"
    launcher.parent.mkdir(parents=True)
    launcher.write_bytes(b"ghidra")
    properties = root / "Ghidra" / "application.properties"
    properties.parent.mkdir(parents=True)
    properties.write_text("application.version=12.0.4\n", encoding="utf-8")
    bwrap = tmp_path / "bwrap"
    bwrap.write_bytes(b"bwrap")
    artifact = tmp_path / "sample.bin"
    artifact.write_bytes(b"authorized")

    def resolver(name):
        return {"analyzeHeadless": str(launcher), "bwrap": str(bwrap)}.get(name)

    manager = ToolRuntimeManager(
        resolver=resolver,
        runner=lambda argv, timeout: (0, "bubblewrap 0.11", "")
        if argv[0] == str(bwrap) else (1, "", "unexpected"),
    )
    ticket = issue_offline_execution_ticket(
        asset_kind=AssetKind.EXECUTABLE,
        method=GHIDRA,
        scope_digest=_SCOPE,
        availability=CapabilityAvailability(
            artifact_available=True,
            sandbox_available=True,
        ),
    )
    calls = []

    def ghidra_runner(argv, workspace, timeout, env, maximum_output_bytes):
        calls.append(argv)
        (workspace / "ghidra.log").write_text("complete", encoding="utf-8")
        return GhidraSandboxProcessResult(0, b"ok", b"")

    outcome = execute_offline_asset_method(
        GHIDRA,
        ticket=ticket,
        scope_digest=_SCOPE,
        artifact_path=artifact,
        runtime_manager=manager,
        pins={},
        ghidra_runner=ghidra_runner,
        timeout=30,
    )
    assert outcome.candidates == ()
    assert outcome.ghidra is not None
    assert outcome.local_cli is None
    assert outcome.internal is None
    assert outcome.observations[0].kind == "binary_analysis"
    assert outcome.provenance["execution_mode"] == "bubblewrap_ghidra"
    assert outcome.provenance["sandbox"]["network_shared"] is False
    assert "--unshare-all" in calls[0]
    assert "--share-net" not in calls[0]


def test_ticket_issuer_refuses_network_state_change_and_unregistered_methods():
    network = DeepScannerMethod(
        "scanner", "network", ("scanner", "{target}"),
        local_only=True, requires_network=True,
    )
    with pytest.raises(AssetExecutionTicketError, match="network-capable"):
        issue_offline_execution_ticket(
            asset_kind=AssetKind.DOMAIN,
            method=network,
            scope_digest=_SCOPE,
            availability=CapabilityAvailability(),
        )

    changing = DeepScannerMethod(
        "scanner", "changing", ("scanner", "{artifact}"),
        local_only=True, state_change_possible=True,
    )
    with pytest.raises(AssetExecutionTicketError, match="state-changing"):
        issue_offline_execution_ticket(
            asset_kind=AssetKind.EXECUTABLE,
            method=changing,
            scope_digest=_SCOPE,
            availability=CapabilityAvailability(artifact_available=True),
        )

    internal = DeepScannerMethod("aegis-unimplemented", "offline", local_only=True)
    with pytest.raises(AssetExecutionTicketError, match="not registered"):
        issue_offline_execution_ticket(
            asset_kind=AssetKind.EXECUTABLE,
            method=internal,
            scope_digest=_SCOPE,
            availability=CapabilityAvailability(artifact_available=True),
        )


def test_router_rejects_scope_and_method_ticket_mismatch(tmp_path):
    artifact = tmp_path / "a.bin"
    artifact.write_bytes(b"x")
    ticket = _artifact_ticket(GRYPE)
    with pytest.raises(AssetExecutionRouteError, match="scope digest mismatch"):
        execute_offline_asset_method(
            GRYPE,
            ticket=ticket,
            scope_digest="scope:other",
            artifact_path=artifact,
        )
    with pytest.raises(AssetExecutionRouteError, match="method mismatch"):
        execute_offline_asset_method(
            SYFT,
            ticket=ticket,
            scope_digest=_SCOPE,
            artifact_path=artifact,
        )


def test_router_does_not_treat_remote_string_as_local_artifact(tmp_path):
    ticket = _artifact_ticket(GRYPE)
    manager = ToolRuntimeManager(resolver=lambda _name: None)
    with pytest.raises(Exception, match="existing local path"):
        execute_offline_asset_method(
            GRYPE,
            ticket=ticket,
            scope_digest=_SCOPE,
            artifact_path="https://example.com/file.tar",
            runtime_manager=manager,
            pins={},
        )
