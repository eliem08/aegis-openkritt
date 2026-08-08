from __future__ import annotations

import hashlib

import httpx
import pytest

from aegis.ai.mobsf_adapter import MobSFConfig, MobSFError, MobSFStaticAdapter


def _artifact(tmp_path, name="demo.apk", payload=b"authorized-mobile-artifact"):
    path = tmp_path / name
    path.write_bytes(payload)
    return path


def _client(handler):
    return httpx.Client(
        base_url="http://127.0.0.1:8000",
        transport=httpx.MockTransport(handler),
    )


def test_remote_mobsf_service_is_rejected():
    with pytest.raises(ValueError, match="loopback"):
        MobSFConfig(base_url="https://mobsf.live", api_key="secret")
    with pytest.raises(ValueError, match="loopback"):
        MobSFConfig(base_url="http://example.com:8000", api_key="secret")


def test_static_flow_uploads_scans_normalizes_and_deletes(tmp_path):
    artifact = _artifact(tmp_path)
    calls = []
    key = "local-api-key"

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path, request.headers.get("X-Mobsf-Api-Key")))
        assert request.headers.get("X-Mobsf-Api-Key") == key
        if request.url.path == "/api/v1/upload":
            return httpx.Response(
                200,
                json={"hash": "a" * 32, "scan_type": "apk", "file_name": "demo.apk"},
            )
        if request.url.path == "/api/v1/scan":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/api/v1/report_json":
            return httpx.Response(
                200,
                json={
                    "version": "v4.4.6",
                    "app_name": "Demo",
                    "package_name": "com.example.demo",
                    "code_analysis": {
                        "findings": {
                            "android_logging": {
                                "severity": "high",
                                "title": "Sensitive data may be logged",
                                "description": "Application logging can expose sensitive values.",
                                "cwe": "CWE-532",
                                "files": ["src/main/java/Demo.java"],
                                "line": 42,
                            }
                        }
                    },
                    "manifest_analysis": {
                        "manifest_findings": [
                            {
                                "severity": "warning",
                                "rule": "app_allowbackup",
                                "description": "Application backups are enabled.",
                            }
                        ]
                    },
                    # Raw sensitive-looking data may exist in a full report but is deliberately
                    # not retained in MobSFScanResult or candidate metadata.
                    "secrets": {"api_token": "DO-NOT-PERSIST"},
                },
            )
        if request.url.path == "/api/v1/delete_scan":
            return httpx.Response(200, json={"deleted": "yes"})
        raise AssertionError(f"unexpected MobSF endpoint: {request.url.path}")

    config = MobSFConfig(api_key=key)
    with _client(handler) as client:
        result = MobSFStaticAdapter(config, client=client).scan(artifact)

    assert [path for _method, path, _key in calls] == [
        "/api/v1/upload",
        "/api/v1/scan",
        "/api/v1/report_json",
        "/api/v1/delete_scan",
    ]
    assert all("dynamic" not in path for _method, path, _key in calls)
    assert result.cleanup_deleted is True
    assert result.artifact_sha256 == hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert result.report_metadata["version"] == "v4.4.6"
    assert len(result.findings) == 2
    code = next(
        row for row in result.findings
        if (row.get("json_answer") or {}).get("vulnerability_type") == "CWE-532"
    )
    assert code["source"] == "aegis:tool:mobsf"
    assert code["validation_status"] == "unverified"
    assert code["json_answer"]["file_path"] == "src/main/java/Demo.java"
    assert key not in repr(result)
    assert "DO-NOT-PERSIST" not in repr(result)


def test_cleanup_runs_after_report_failure(tmp_path):
    artifact = _artifact(tmp_path)
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/api/v1/upload":
            return httpx.Response(200, json={"hash": "b" * 32, "scan_type": "apk"})
        if request.url.path == "/api/v1/scan":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/api/v1/report_json":
            return httpx.Response(500, json={"error": "report unavailable"})
        if request.url.path == "/api/v1/delete_scan":
            return httpx.Response(200, json={"deleted": "yes"})
        raise AssertionError(request.url.path)

    with _client(handler) as client:
        adapter = MobSFStaticAdapter(MobSFConfig(api_key="key"), client=client)
        with pytest.raises(MobSFError, match="HTTP 500"):
            adapter.scan(artifact)

    assert calls[-1] == "/api/v1/delete_scan"


def test_invalid_upload_hash_stops_before_scan_and_cannot_skip_cleanup_logic(tmp_path):
    artifact = _artifact(tmp_path)
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/api/v1/upload":
            return httpx.Response(200, json={"hash": "not-a-hash"})
        raise AssertionError("scan/report must never run after invalid upload identity")

    with _client(handler) as client:
        adapter = MobSFStaticAdapter(MobSFConfig(api_key="key"), client=client)
        with pytest.raises(MobSFError, match="valid scan hash"):
            adapter.scan(artifact)
    assert calls == ["/api/v1/upload"]


def test_artifact_type_and_size_are_checked_before_http(tmp_path):
    bad = _artifact(tmp_path, name="sample.exe")
    called = []

    def handler(request: httpx.Request) -> httpx.Response:
        called.append(request.url.path)
        raise AssertionError("HTTP must not run for rejected artifact")

    with _client(handler) as client:
        adapter = MobSFStaticAdapter(MobSFConfig(api_key="key"), client=client)
        with pytest.raises(ValueError, match="unsupported"):
            adapter.scan(bad)
    assert called == []

    large = _artifact(tmp_path, name="large.apk", payload=b"12345")
    config = MobSFConfig(api_key="key", max_artifact_bytes=4)
    with _client(handler) as client:
        adapter = MobSFStaticAdapter(config, client=client)
        with pytest.raises(ValueError, match="size limit"):
            adapter.scan(large)
    assert called == []
