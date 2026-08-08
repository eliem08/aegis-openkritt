from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from aegis.ai.jarvis.asset_capabilities import GRYPE, MOBSF
from aegis.ai.jarvis.asset_cli_executor import CliProcessResult
from aegis.ai.jarvis.asset_deep_capabilities import DeepScannerMethod
from aegis.ai.jarvis.asset_execution_router import (
    AssetExecutionRouteError,
    execute_offline_asset_method,
)
from aegis.ai.mobsf_adapter import MobSFConfig
from aegis.ai.tool_runtime import ToolRuntimeManager


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

    outcome = execute_offline_asset_method(
        GRYPE,
        artifact_path=artifact,
        runtime_manager=manager,
        pins={},
        runner=runner,
    )
    assert len(outcome.candidates) == 1
    assert outcome.candidates[0]["validation_status"] == "unverified"
    assert outcome.provenance["verification_state"] == "candidate"
    assert outcome.local_cli is not None
    assert outcome.internal is None


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
    try:
        outcome = execute_offline_asset_method(
            MOBSF,
            artifact_path=artifact,
            mobsf_config=MobSFConfig(api_key="key"),
            mobsf_client=client,
        )
    finally:
        client.close()
    assert outcome.internal is not None
    assert outcome.local_cli is None
    assert outcome.observations[0].kind == "internal_scanner_run"


def test_router_refuses_network_state_change_and_unregistered_internal_before_execution(tmp_path):
    network = DeepScannerMethod(
        "scanner", "network", ("scanner", "{target}"),
        local_only=True, requires_network=True,
    )
    with pytest.raises(AssetExecutionRouteError, match="network-capable"):
        execute_offline_asset_method(network, target_path=tmp_path)

    changing = DeepScannerMethod(
        "scanner", "changing", ("scanner", "{artifact}"),
        local_only=True, state_change_possible=True,
    )
    with pytest.raises(AssetExecutionRouteError, match="state-changing"):
        execute_offline_asset_method(changing, artifact_path=tmp_path)

    internal = DeepScannerMethod("aegis-unimplemented", "offline", local_only=True)
    with pytest.raises(AssetExecutionRouteError, match="no concrete offline executor"):
        execute_offline_asset_method(internal, artifact_path=tmp_path)


def test_router_does_not_treat_local_target_string_as_remote_endpoint(tmp_path):
    method = DeepScannerMethod(
        "scanner", "offline", ("scanner", "{target}"), local_only=True
    )
    manager = ToolRuntimeManager(resolver=lambda _name: None)
    with pytest.raises(Exception, match="existing local path|unavailable"):
        execute_offline_asset_method(
            method,
            target_path="https://example.com",
            runtime_manager=manager,
            pins={},
        )
