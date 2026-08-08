from __future__ import annotations

import plistlib
import struct
import zipfile
from pathlib import Path

import httpx

from aegis.ai.jarvis.ios_pipeline import cleanup_ios_pipeline, run_ios_static_pipeline
from aegis.ai.mobsf_adapter import MobSFConfig


def _macho_arm64() -> bytes:
    command = bytearray(16)
    struct.pack_into("<IIII", command, 0, 0x1D, 16, 0x100, 32)
    header = bytearray(32)
    header[:4] = b"\xcf\xfa\xed\xfe"
    struct.pack_into("<IIIIII", header, 4, 0x0100000C, 0, 2, 1, 16, 0x00200000)
    struct.pack_into("<I", header, 28, 0)
    return bytes(header + command + b"\x00" * 128)


def _ipa(tmp_path):
    ipa = tmp_path / "Demo.ipa"
    plist = {
        "CFBundleIdentifier": "com.example.demo",
        "CFBundleDisplayName": "Demo",
        "CFBundleVersion": "1",
        "CFBundleShortVersionString": "1.0",
        "CFBundleExecutable": "DemoExec",
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
    }
    with zipfile.ZipFile(ipa, "w", compression=zipfile.ZIP_STORED) as bundle:
        bundle.writestr("Payload/Demo.app/Info.plist", plistlib.dumps(plist))
        bundle.writestr("Payload/Demo.app/DemoExec", _macho_arm64())
        bundle.writestr("Payload/Demo.app/Frameworks/Noise.framework/readme.txt", b"not macho")
    return ipa


def _mobsf_client():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/upload":
            return httpx.Response(200, json={"hash": "f" * 32, "scan_type": "ipa"})
        if request.url.path == "/api/v1/scan":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/api/v1/report_json":
            return httpx.Response(
                200,
                json={
                    "code_analysis": {
                        "rule": {
                            "title": "Review insecure storage",
                            "description": "candidate only",
                            "severity": "warning",
                            "file": "Payload/Demo.app/DemoExec",
                        }
                    }
                },
            )
        if request.url.path == "/api/v1/delete_scan":
            return httpx.Response(200, json={"deleted": "yes"})
        raise AssertionError(request.url.path)

    return httpx.Client(
        base_url="http://127.0.0.1:8000",
        transport=httpx.MockTransport(handler),
    )


def test_pipeline_combines_ipa_posture_main_macho_and_mobsf_candidates(tmp_path):
    ipa = _ipa(tmp_path)
    client = _mobsf_client()
    try:
        report = run_ios_static_pipeline(
            ipa,
            scope_digest="scope:ios-pipeline",
            mobsf_config=MobSFConfig(api_key="key"),
            mobsf_client=client,
            workspace_root=tmp_path / "work",
        )
    finally:
        client.close()
    statuses = {stage.stage: stage.status for stage in report.stages}
    assert statuses["ipa_metadata"] == "complete"
    assert statuses["macho_main"] == "complete"
    assert statuses["macho_frameworks"] == "partial"
    assert statuses["mobsf"] == "complete"
    assert report.static_report is None
    assert not list((tmp_path / "work").glob("aegis-rootfs-*"))
    assert any(row["source"] == "aegis:ios-static" for row in report.candidates)
    assert any(row["source"] == "aegis:tool:mobsf" for row in report.candidates)
    assert all(row["validation_status"] == "unverified" for row in report.candidates)
    main = next(
        item for item in report.observations
        if item.get("kind") == "macho_metadata" and item.get("label") == "main_executable"
    )
    assert main["architectures"] == ("arm64",)
    assert main["pie"] is True
    assert main["code_signature"] is True


def test_pipeline_can_retain_and_explicitly_cleanup_extraction(tmp_path):
    ipa = _ipa(tmp_path)
    report = run_ios_static_pipeline(
        ipa,
        scope_digest="scope:ios-pipeline",
        mobsf_config=None,
        workspace_root=tmp_path / "work",
        retain_extraction=True,
    )
    assert report.static_report is not None
    root = Path(report.static_report.extraction.root)
    assert root.is_dir()
    assert {stage.stage: stage.status for stage in report.stages}["mobsf"] == "skipped"
    cleanup_ios_pipeline(report)
    assert report.static_report is None
    assert not root.exists()
