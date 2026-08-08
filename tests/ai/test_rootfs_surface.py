from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from aegis.ai.jarvis.rootfs_surface import RootfsSurfaceError, correlate_rootfs_surface
from aegis.ai.jarvis.safe_archive import cleanup_safe_archive, extract_safe_archive


def _rootfs(tmp_path):
    archive = tmp_path / "firmware.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as bundle:
        bundle.writestr("www/index.html", '<a href="/admin/login">admin</a>')
        bundle.writestr(
            "etc/nginx.conf",
            "server { listen 8443; location /api/v1/upload { } }",
        )
        bundle.writestr("etc/init.d/S50dropbear", "#!/bin/sh\ndropbear -p 22\n")
        bundle.writestr("var/lib/dpkg/status", "Package: demo\nVersion: 1\n")
        bundle.writestr("etc/ssl/server.crt", "certificate-placeholder")
        bundle.writestr("etc/ssl/server.key", "private-material-not-returned")
        bundle.writestr("usr/bin/demo", b"\x7fELF" + b"\x00" * 128)
    return extract_safe_archive(archive, workspace_root=tmp_path / "work")


def test_surface_report_maps_web_service_init_package_tls_and_elf_without_secret_values(tmp_path):
    extraction = _rootfs(tmp_path)
    try:
        report = correlate_rootfs_surface(extraction)
        assert report.scanned_files == 7
        assert {item.path for item in report.web_files} >= {"www/index.html"}
        assert {item.path for item in report.service_configs} == {"etc/nginx.conf"}
        assert "etc/init.d/S50dropbear" in {item.path for item in report.init_files}
        assert "var/lib/dpkg/status" in {item.path for item in report.package_databases}
        assert {"etc/ssl/server.crt", "etc/ssl/server.key"} <= {
            item.path for item in report.tls_material
        }
        assert "usr/bin/demo" in {item.path for item in report.elf_files}
        assert {22, 8443} <= set(report.listen_port_hints)
        assert {"nginx", "dropbear-ssh"} <= set(report.service_hints)
        assert "/admin/login" in report.route_hints
        assert "/api/v1/upload" in report.route_hints
        serialized = repr(report.as_dict())
        assert "private-material-not-returned" not in serialized
        assert len(report.rootfs_digest) == 64
    finally:
        cleanup_safe_archive(extraction)


def test_surface_digest_changes_when_rootfs_content_changes(tmp_path):
    extraction = _rootfs(tmp_path)
    try:
        before = correlate_rootfs_surface(extraction).rootfs_digest
        (Path(extraction.root) / "www/index.html").write_text("changed", encoding="utf-8")
        after = correlate_rootfs_surface(extraction).rootfs_digest
        assert before != after
    finally:
        cleanup_safe_archive(extraction)


def test_symlink_insertion_is_rejected(tmp_path):
    extraction = _rootfs(tmp_path)
    try:
        link = Path(extraction.root) / "etc/host"
        try:
            link.symlink_to("/etc/passwd")
        except OSError:
            pytest.skip("symlink creation unavailable")
        with pytest.raises(RootfsSurfaceError, match="symlink"):
            correlate_rootfs_surface(extraction)
    finally:
        cleanup_safe_archive(extraction)


def test_surface_limits_fail_closed(tmp_path):
    extraction = _rootfs(tmp_path)
    try:
        with pytest.raises(RootfsSurfaceError, match="file-count"):
            correlate_rootfs_surface(extraction, max_files=2)
        with pytest.raises(RootfsSurfaceError, match="byte limit"):
            correlate_rootfs_surface(extraction, max_total_bytes=16)
    finally:
        cleanup_safe_archive(extraction)
