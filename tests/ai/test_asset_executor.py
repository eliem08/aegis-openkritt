from __future__ import annotations

import httpx
import pytest

from aegis.ai.jarvis.asset_capabilities import MOBSF
from aegis.ai.jarvis.asset_deep_capabilities import DeepScannerMethod
from aegis.ai.jarvis.asset_executor import (
    InternalAssetExecutorError,
    execute_internal_asset_method,
)
from aegis.ai.mobsf_adapter import MobSFConfig


def test_internal_executor_dispatches_only_mobsf_static(tmp_path):
    artifact = tmp_path / "demo.apk"
    artifact.write_bytes(b"authorized")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/upload":
            return httpx.Response(200, json={"hash": "c" * 32, "scan_type": "apk"})
        if request.url.path == "/api/v1/scan":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/api/v1/report_json":
            return httpx.Response(
                200,
                json={
                    "code_analysis": {
                        "findings": {
                            "rule": {
                                "severity": "high",
                                "title": "Risky mobile behavior",
                                "description": "Static evidence requires independent validation.",
                                "cwe": "CWE-200",
                            }
                        }
                    }
                },
            )
        if request.url.path == "/api/v1/delete_scan":
            return httpx.Response(200, json={"deleted": "yes"})
        raise AssertionError(request.url.path)

    client = httpx.Client(
        base_url="http://127.0.0.1:8000",
        transport=httpx.MockTransport(handler),
    )
    try:
        execution = execute_internal_asset_method(
            MOBSF,
            artifact_path=artifact,
            mobsf_config=MobSFConfig(api_key="key"),
            mobsf_client=client,
        )
    finally:
        client.close()

    assert execution.tool == "MobSF"
    assert execution.method == "rest-static-analysis"
    assert len(execution.candidates) == 1
    assert execution.candidates[0]["validation_status"] == "unverified"
    assert execution.provenance["verification_state"] == "candidate"
    assert execution.provenance["cleanup_deleted"] is True


def test_internal_executor_requires_artifact_and_never_shell_falls_through():
    with pytest.raises(InternalAssetExecutorError, match="authorized artifact"):
        execute_internal_asset_method(MOBSF, mobsf_config=MobSFConfig(api_key="key"))

    unsupported = DeepScannerMethod("aegis-unknown", "do-something")
    with pytest.raises(InternalAssetExecutorError, match="unsupported"):
        execute_internal_asset_method(unsupported, artifact_path="anything.apk")
