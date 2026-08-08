from __future__ import annotations

import json
import zipfile
from pathlib import Path

from aegis.ai.jarvis.asset_cli_executor import CliProcessResult
from aegis.ai.jarvis.firmware_pipeline import run_firmware_offline_pipeline
from aegis.ai.jarvis.rootfs_followup import ROOTFS_GRYPE
from aegis.ai.jarvis.safe_archive import cleanup_safe_archive, SafeArchiveExtraction
from aegis.ai.tool_runtime import ToolRuntimeManager


def _firmware_zip(tmp_path):
    archive = tmp_path / "firmware.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as bundle:
        bundle.writestr("www/index.html", '<a href="/admin/login">admin</a>')
        bundle.writestr("etc/nginx.conf", "server { listen 8080; }")
        bundle.writestr("var/lib/dpkg/status", "Package: demo\nVersion: 1\n")
    return archive


def test_pipeline_metadata_extract_surface_grype_and_cleanup(tmp_path):
    firmware = _firmware_zip(tmp_path)
    grype = tmp_path / "grype"
    grype.write_bytes(b"grype")
    manager = ToolRuntimeManager(
        resolver=lambda name: str(grype) if name == "grype" else None,
        runner=lambda argv, timeout: (0, "grype 1.0", ""),
    )
    payload = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2099-2000",
                    "severity": "High",
                    "description": "demo",
                },
                "artifact": {
                    "name": "demo",
                    "version": "1",
                    "locations": [{"path": "/usr/lib/demo"}],
                },
            }
        ]
    }

    report = run_firmware_offline_pipeline(
        firmware,
        scope_digest="scope:pipeline",
        followup_methods=(ROOTFS_GRYPE,),
        workspace_root=tmp_path / "work",
        runtime_manager=manager,
        pins={},
        runner=lambda argv, workspace, timeout, env, maximum_output_bytes: CliProcessResult(
            0, json.dumps(payload).encode(), b""
        ),
    )
    stages = {item.stage: item.status for item in report.stages}
    assert stages == {
        "metadata": "complete",
        "extract": "complete",
        "surface": "complete",
        "rootfs_followups": "complete",
    }
    assert len(report.candidates) == 1
    assert report.candidates[0]["validation_status"] == "unverified"
    assert report.followup_tools == ["grype/rootfs-vulnerability-scan"]
    assert report.followup_errors == {}
    assert report.needs_isolated_filesystem_backend is False
    assert report.rootfs_retained is False
    assert report.rootfs_path == ""
    assert not list((tmp_path / "work").glob("aegis-rootfs-*"))
    kinds = {observation.kind for observation in report.observations}
    assert {"firmware_metadata", "rootfs_extraction", "rootfs_surface", "scanner_run"} <= kinds


def test_raw_squashfs_stops_at_isolated_filesystem_backend_requirement(tmp_path):
    firmware = tmp_path / "rootfs.squashfs"
    firmware.write_bytes(b"hsqs" + b"\x00" * 8192)
    report = run_firmware_offline_pipeline(
        firmware,
        scope_digest="scope:pipeline",
        followup_methods=(),
        workspace_root=tmp_path / "work",
        pins={},
    )
    stages = [(item.stage, item.status) for item in report.stages]
    assert stages[0] == ("metadata", "complete")
    assert stages[1] == ("extract", "unsupported")
    assert report.needs_isolated_filesystem_backend is True
    assert report.candidates == []
    assert not list((tmp_path / "work").glob("aegis-rootfs-*"))


def test_pipeline_records_unavailable_followup_without_hiding_safe_stages(tmp_path):
    firmware = _firmware_zip(tmp_path)
    unavailable = ToolRuntimeManager(resolver=lambda _name: None)
    report = run_firmware_offline_pipeline(
        firmware,
        scope_digest="scope:pipeline",
        followup_methods=(ROOTFS_GRYPE,),
        workspace_root=tmp_path / "work",
        runtime_manager=unavailable,
        pins={},
    )
    stages = {item.stage: item.status for item in report.stages}
    assert stages["metadata"] == "complete"
    assert stages["extract"] == "complete"
    assert stages["surface"] == "complete"
    assert stages["rootfs_followups"] == "partial"
    assert "grype/rootfs-vulnerability-scan" in report.followup_errors
    assert report.candidates == []


def test_pipeline_can_retain_rootfs_only_when_explicitly_requested(tmp_path):
    firmware = _firmware_zip(tmp_path)
    report = run_firmware_offline_pipeline(
        firmware,
        scope_digest="scope:pipeline",
        followup_methods=(),
        workspace_root=tmp_path / "work",
        retain_rootfs=True,
        pins={},
    )
    assert report.rootfs_retained is True
    root = Path(report.rootfs_path)
    assert root.is_dir()
    extraction = SafeArchiveExtraction(
        archive_type="zip",
        archive_sha256="",
        archive_size=0,
        root=str(root),
        file_count=0,
        total_bytes=0,
        entries=(),
    )
    cleanup_safe_archive(extraction)
    assert not root.exists()
