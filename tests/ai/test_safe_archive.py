from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from aegis.ai.jarvis.asset_execution_ticket import (
    AssetExecutionTicketError,
    CapabilityAvailability,
)
from aegis.ai.jarvis.firmware_execution import (
    FirmwareExecutionError,
    cleanup_safe_archive,
    execute_safe_rootfs_extraction,
    issue_safe_rootfs_ticket,
)
from aegis.ai.jarvis.safe_archive import SafeArchiveError, SafeArchiveLimits, extract_safe_archive


def _zip(path: Path, entries: dict[str, bytes], *, compression=zipfile.ZIP_DEFLATED) -> None:
    with zipfile.ZipFile(path, "w", compression=compression) as bundle:
        for name, payload in entries.items():
            bundle.writestr(name, payload)


def _plain_tar(path: Path, entries: dict[str, bytes]) -> None:
    with tarfile.open(path, "w") as bundle:
        for name, payload in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            bundle.addfile(info, io.BytesIO(payload))


def test_zip_extracts_bounded_files_without_preserving_archive_permissions(tmp_path):
    archive = tmp_path / "firmware.zip"
    _zip(archive, {"etc/config": b"safe", "www/index.html": b"<html/>"})
    extraction = extract_safe_archive(archive, workspace_root=tmp_path / "work")
    root = Path(extraction.root)
    try:
        assert extraction.archive_type == "zip"
        assert extraction.file_count == 2
        assert extraction.total_bytes == len(b"safe") + len(b"<html/>")
        assert (root / "etc/config").read_bytes() == b"safe"
        assert (root / "www/index.html").read_bytes() == b"<html/>"
        assert all(item.sha256 for item in extraction.entries)
        assert len(extraction.archive_sha256) == 64
    finally:
        cleanup_safe_archive(extraction)
    assert not root.exists()


def test_plain_tar_accepts_leading_dot_slash_but_rejects_links_and_traversal(tmp_path):
    archive = tmp_path / "firmware.tar"
    _plain_tar(archive, {"./etc/inittab": b"::sysinit:/etc/init.d/rcS"})
    extraction = extract_safe_archive(archive)
    root = Path(extraction.root)
    try:
        assert (root / "etc/inittab").is_file()
    finally:
        cleanup_safe_archive(extraction)

    traversal = tmp_path / "traversal.tar"
    _plain_tar(traversal, {"../escape": b"no"})
    with pytest.raises(SafeArchiveError, match="traversal"):
        extract_safe_archive(traversal, workspace_root=tmp_path / "work")
    assert not (tmp_path / "escape").exists()

    symlink = tmp_path / "link.tar"
    with tarfile.open(symlink, "w") as bundle:
        info = tarfile.TarInfo("etc/passwd-link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        bundle.addfile(info)
    with pytest.raises(SafeArchiveError, match="links/devices"):
        extract_safe_archive(symlink)


def test_zip_path_traversal_and_compression_bomb_ratio_are_rejected(tmp_path):
    traversal = tmp_path / "traversal.zip"
    _zip(traversal, {"../../escape": b"no"})
    with pytest.raises(SafeArchiveError, match="traversal"):
        extract_safe_archive(traversal)

    bomb = tmp_path / "bomb.zip"
    _zip(bomb, {"huge.txt": b"A" * 200_000})
    with pytest.raises(SafeArchiveError, match="compression-ratio"):
        extract_safe_archive(
            bomb,
            limits=SafeArchiveLimits(max_compression_ratio=2.0),
        )


def test_compressed_tar_and_raw_filesystem_images_require_isolated_backend(tmp_path):
    compressed = tmp_path / "firmware.tar.gz"
    with tarfile.open(compressed, "w:gz") as bundle:
        payload = b"rootfs"
        info = tarfile.TarInfo("etc/config")
        info.size = len(payload)
        bundle.addfile(info, io.BytesIO(payload))
    with pytest.raises(SafeArchiveError, match="only ZIP or uncompressed TAR"):
        extract_safe_archive(compressed)

    squashfs = tmp_path / "rootfs.squashfs"
    squashfs.write_bytes(b"hsqs" + b"\x00" * 4096)
    with pytest.raises(SafeArchiveError, match="only ZIP or uncompressed TAR"):
        extract_safe_archive(squashfs)


def test_limits_fail_closed_and_cleanup_partial_output(tmp_path):
    archive = tmp_path / "many.zip"
    _zip(archive, {"a": b"1", "b": b"2"}, compression=zipfile.ZIP_STORED)
    work = tmp_path / "work"
    with pytest.raises(SafeArchiveError, match="file-count"):
        extract_safe_archive(
            archive,
            workspace_root=work,
            limits=SafeArchiveLimits(max_files=1),
        )
    assert not list(work.glob("aegis-rootfs-*"))


def test_ticketed_firmware_extension_requires_authorized_firmware_and_emits_observation_only(tmp_path):
    with pytest.raises(AssetExecutionTicketError, match="authorized_firmware"):
        issue_safe_rootfs_ticket(
            scope_digest="scope:firmware",
            availability=CapabilityAvailability(),
        )

    archive = tmp_path / "firmware.zip"
    _zip(archive, {"etc/config": b"safe"}, compression=zipfile.ZIP_STORED)
    ticket = issue_safe_rootfs_ticket(
        scope_digest="scope:firmware",
        availability=CapabilityAvailability(firmware_available=True),
    )
    outcome = execute_safe_rootfs_extraction(
        ticket=ticket,
        scope_digest="scope:firmware",
        firmware_path=archive,
        workspace_root=tmp_path / "work",
    )
    root = Path(outcome.extraction.root)
    try:
        assert outcome.candidates == ()
        assert outcome.observations[0].kind == "rootfs_extraction"
        assert outcome.provenance["verification_state"] == "observation"
        assert outcome.provenance["raw_filesystem_images_supported"] is False
        assert root.is_dir()
    finally:
        cleanup_safe_archive(outcome.extraction)
    assert not root.exists()


def test_ticket_scope_mismatch_is_rejected_before_extraction(tmp_path):
    archive = tmp_path / "firmware.zip"
    _zip(archive, {"etc/config": b"safe"}, compression=zipfile.ZIP_STORED)
    ticket = issue_safe_rootfs_ticket(
        scope_digest="scope:one",
        availability=CapabilityAvailability(firmware_available=True),
    )
    with pytest.raises(FirmwareExecutionError, match="scope digest mismatch"):
        execute_safe_rootfs_extraction(
            ticket=ticket,
            scope_digest="scope:two",
            firmware_path=archive,
        )
