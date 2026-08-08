"""Bounded extraction for authorized firmware archives.

Only ZIP and TAR-family containers are supported. Extraction is implemented in Python without
executing archive helpers, preserving archive permissions, following links, creating devices, or
writing outside the private output root. Raw filesystem images (SquashFS/JFFS2/UBI/etc.) are
intentionally unsupported here and require a separately isolated backend.
"""

from __future__ import annotations

import hashlib
import shutil
import stat
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


class SafeArchiveError(RuntimeError):
    pass


@dataclass(frozen=True)
class SafeArchiveLimits:
    max_files: int = 20_000
    max_total_bytes: int = 2 * 1024 * 1024 * 1024
    max_file_bytes: int = 256 * 1024 * 1024
    max_compression_ratio: float = 200.0
    max_hash_bytes: int = 64 * 1024 * 1024

    def validate(self) -> None:
        if not 1 <= self.max_files <= 200_000:
            raise SafeArchiveError("max_files is outside the allowed range")
        if not 1024 <= self.max_total_bytes <= 16 * 1024 * 1024 * 1024:
            raise SafeArchiveError("max_total_bytes is outside the allowed range")
        if not 1024 <= self.max_file_bytes <= self.max_total_bytes:
            raise SafeArchiveError("max_file_bytes is outside the allowed range")
        if not 1.0 <= float(self.max_compression_ratio) <= 10_000.0:
            raise SafeArchiveError("max_compression_ratio is outside the allowed range")


@dataclass(frozen=True)
class ExtractedEntry:
    relative_path: str
    size_bytes: int
    sha256: str = ""


@dataclass(frozen=True)
class SafeArchiveExtraction:
    archive_type: str
    archive_sha256: str
    archive_size: int
    root: str
    file_count: int
    total_bytes: int
    entries: tuple[ExtractedEntry, ...]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_relative(name: str) -> PurePosixPath:
    raw = str(name or "").replace("\\", "/")
    if "\x00" in raw:
        raise SafeArchiveError("archive entry contains a NUL byte")
    path = PurePosixPath(raw)
    if path.is_absolute() or not path.parts:
        raise SafeArchiveError("archive entry path is absolute or empty")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise SafeArchiveError("archive entry contains traversal components")
    if path.parts[0].endswith(":"):
        raise SafeArchiveError("archive entry contains a drive-qualified path")
    return path


def _copy_bounded(source, destination: Path, expected_size: int, limits: SafeArchiveLimits) -> int:
    destination.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with destination.open("wb") as out:
        while chunk := source.read(1024 * 1024):
            written += len(chunk)
            if written > limits.max_file_bytes or written > expected_size + 1024:
                raise SafeArchiveError("archive entry exceeded its bounded declared size")
            out.write(chunk)
    if written != expected_size:
        raise SafeArchiveError("archive entry size differs from its declared size")
    return written


def _entry_record(path: Path, root: Path, limits: SafeArchiveLimits) -> ExtractedEntry:
    size = path.stat().st_size
    digest = _sha256_file(path) if size <= limits.max_hash_bytes else ""
    return ExtractedEntry(path.relative_to(root).as_posix(), size, digest)


def _validate_counts(count: int, total: int, size: int, limits: SafeArchiveLimits) -> tuple[int, int]:
    count += 1
    total += size
    if count > limits.max_files:
        raise SafeArchiveError("archive exceeds file-count limit")
    if size > limits.max_file_bytes:
        raise SafeArchiveError("archive entry exceeds per-file size limit")
    if total > limits.max_total_bytes:
        raise SafeArchiveError("archive exceeds total extracted-size limit")
    return count, total


def _extract_zip(archive: Path, root: Path, limits: SafeArchiveLimits) -> tuple[int, int, list[ExtractedEntry]]:
    count = total = 0
    entries: list[ExtractedEntry] = []
    with zipfile.ZipFile(archive) as bundle:
        infos = bundle.infolist()
        for info in infos:
            relative = _safe_relative(info.filename)
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise SafeArchiveError("ZIP symlinks are not allowed")
            if info.flag_bits & 0x1:
                raise SafeArchiveError("encrypted ZIP entries are not allowed")
            if info.is_dir():
                (root / relative).mkdir(parents=True, exist_ok=True)
                continue
            count, total = _validate_counts(count, total, int(info.file_size), limits)
            if info.file_size > 0:
                compressed = max(1, int(info.compress_size))
                ratio = float(info.file_size) / compressed
                if ratio > limits.max_compression_ratio:
                    raise SafeArchiveError("ZIP entry exceeds compression-ratio limit")
            destination = root / relative
            with bundle.open(info, "r") as source:
                _copy_bounded(source, destination, int(info.file_size), limits)
            entries.append(_entry_record(destination, root, limits))
    return count, total, entries


def _extract_tar(archive: Path, root: Path, limits: SafeArchiveLimits) -> tuple[int, int, list[ExtractedEntry]]:
    count = total = 0
    entries: list[ExtractedEntry] = []
    try:
        bundle = tarfile.open(archive, mode="r:*")
    except tarfile.TarError as exc:
        raise SafeArchiveError("unsupported or malformed TAR archive") from exc
    with bundle:
        members = bundle.getmembers()
        for member in members:
            relative = _safe_relative(member.name)
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise SafeArchiveError("TAR links/devices/FIFOs are not allowed")
            if member.isdir():
                (root / relative).mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise SafeArchiveError("unsupported TAR member type")
            count, total = _validate_counts(count, total, int(member.size), limits)
            source = bundle.extractfile(member)
            if source is None:
                raise SafeArchiveError("TAR regular file could not be read")
            destination = root / relative
            with source:
                _copy_bounded(source, destination, int(member.size), limits)
            entries.append(_entry_record(destination, root, limits))
    return count, total, entries


def extract_safe_archive(
    archive_path: str | Path,
    *,
    workspace_root: str | Path | None = None,
    limits: SafeArchiveLimits | None = None,
) -> SafeArchiveExtraction:
    """Extract a bounded ZIP/TAR-family archive into a private retained directory."""
    archive = Path(archive_path).expanduser().resolve()
    if not archive.is_file():
        raise SafeArchiveError("archive must be an existing regular file")
    constraints = limits or SafeArchiveLimits()
    constraints.validate()
    root_parent = Path(workspace_root).expanduser().resolve() if workspace_root else None
    if root_parent is not None:
        root_parent.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="aegis-rootfs-", dir=str(root_parent) if root_parent else None))
    try:
        if zipfile.is_zipfile(archive):
            archive_type = "zip"
            count, total, entries = _extract_zip(archive, root, constraints)
        elif tarfile.is_tarfile(archive):
            archive_type = "tar"
            count, total, entries = _extract_tar(archive, root, constraints)
        else:
            raise SafeArchiveError(
                "unsupported archive format; raw filesystem images require an isolated backend"
            )
        return SafeArchiveExtraction(
            archive_type=archive_type,
            archive_sha256=_sha256_file(archive),
            archive_size=archive.stat().st_size,
            root=str(root),
            file_count=count,
            total_bytes=total,
            entries=tuple(entries),
        )
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise


def cleanup_safe_archive(extraction: SafeArchiveExtraction) -> None:
    root = Path(extraction.root).resolve()
    if root.name.startswith("aegis-rootfs-"):
        shutil.rmtree(root, ignore_errors=True)
