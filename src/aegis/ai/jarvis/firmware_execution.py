"""Ticketed firmware-extension execution seam.

This keeps bounded archive extraction on the same execution-ticket integrity contract as the
central asset router without duplicating the base capability planner. It handles only the safe
firmware extension registered in :mod:`asset_capability_extensions` and returns observations,
never vulnerability candidates.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .asset_capabilities import AssetKind
from .asset_capability_extensions import extension_method
from .asset_execution_ticket import (
    AssetExecutionTicket,
    AssetExecutionTicketError,
    CapabilityAvailability,
    _availability_digest,
    _ticket_id,
    verify_offline_execution_ticket,
)
from .asset_normalizers import AssetExecutionObservation
from .firmware_methods import SAFE_ROOTFS_EXTRACT
from .safe_archive import (
    SafeArchiveExtraction,
    SafeArchiveLimits,
    cleanup_safe_archive,
    extract_safe_archive,
)


class FirmwareExecutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class FirmwareExtractionOutcome:
    candidates: tuple[dict, ...]
    observations: tuple[AssetExecutionObservation, ...]
    provenance: dict[str, Any]
    extraction: SafeArchiveExtraction


def issue_safe_rootfs_ticket(
    *,
    scope_digest: str,
    availability: CapabilityAvailability,
) -> AssetExecutionTicket:
    """Issue the rootfs-extraction ticket only when an authorized firmware image is present."""
    scope = str(scope_digest or "").strip()
    if not scope:
        raise AssetExecutionTicketError("scope_digest is required")
    extension = extension_method(
        AssetKind.HARDWARE,
        SAFE_ROOTFS_EXTRACT.tool,
        SAFE_ROOTFS_EXTRACT.method,
        firmware_available=availability.firmware_available,
    )
    if extension is None:
        raise AssetExecutionTicketError("safe rootfs extraction is not registered for hardware")
    if not extension.ready:
        missing = ", ".join(item.value for item in extension.missing_requirements)
        raise AssetExecutionTicketError(
            f"method is blocked by capability extension: {missing or 'authorized_firmware'}"
        )
    requirements = ("authorized_firmware",)
    availability_digest = _availability_digest(availability)
    material = {
        "scope_digest": scope,
        "asset_kind": AssetKind.HARDWARE.value,
        "tool": SAFE_ROOTFS_EXTRACT.tool,
        "method": SAFE_ROOTFS_EXTRACT.method,
        "requirements": requirements,
        "availability_digest": availability_digest,
        "offline_only": True,
    }
    return AssetExecutionTicket(
        ticket_id=_ticket_id(material),
        scope_digest=scope,
        asset_kind=AssetKind.HARDWARE.value,
        tool=SAFE_ROOTFS_EXTRACT.tool,
        method=SAFE_ROOTFS_EXTRACT.method,
        requirements=requirements,
        availability_digest=availability_digest,
        offline_only=True,
    )


def execute_safe_rootfs_extraction(
    *,
    ticket: AssetExecutionTicket,
    scope_digest: str,
    firmware_path: str | Path,
    workspace_root: str | Path | None = None,
    limits: SafeArchiveLimits | None = None,
) -> FirmwareExtractionOutcome:
    """Extract a ZIP/plain-TAR firmware archive after ticket verification."""
    try:
        verify_offline_execution_ticket(
            ticket,
            SAFE_ROOTFS_EXTRACT,
            scope_digest=scope_digest,
        )
    except AssetExecutionTicketError as exc:
        raise FirmwareExecutionError(str(exc)) from exc
    if ticket.asset_kind != AssetKind.HARDWARE.value:
        raise FirmwareExecutionError("safe rootfs extraction ticket must target hardware")
    try:
        extraction = extract_safe_archive(
            firmware_path,
            workspace_root=workspace_root,
            limits=limits,
        )
    except Exception as exc:
        raise FirmwareExecutionError(f"rootfs extraction: {exc}") from exc

    provenance = {
        "adapter": "aegis.ai.jarvis.safe_archive.extract_safe_archive",
        "archive_type": extraction.archive_type,
        "archive_sha256": extraction.archive_sha256,
        "archive_size": extraction.archive_size,
        "file_count": extraction.file_count,
        "total_bytes": extraction.total_bytes,
        "execution_ticket": ticket.ticket_id,
        "scope_digest": ticket.scope_digest,
        "verification_state": "observation",
        "raw_filesystem_images_supported": False,
    }
    observation = AssetExecutionObservation(
        kind="rootfs_extraction",
        tool=SAFE_ROOTFS_EXTRACT.tool,
        method=SAFE_ROOTFS_EXTRACT.method,
        data={
            "archive_type": extraction.archive_type,
            "archive_sha256": extraction.archive_sha256,
            "archive_size": extraction.archive_size,
            "file_count": extraction.file_count,
            "total_bytes": extraction.total_bytes,
            "entries": tuple(
                {
                    "path": item.relative_path,
                    "size_bytes": item.size_bytes,
                    "sha256": item.sha256,
                }
                for item in extraction.entries[:500]
            ),
            "verification_state": "observation",
        },
    )
    return FirmwareExtractionOutcome(
        candidates=(),
        observations=(observation,),
        provenance=provenance,
        extraction=extraction,
    )


__all__ = [
    "FirmwareExecutionError",
    "FirmwareExtractionOutcome",
    "cleanup_safe_archive",
    "execute_safe_rootfs_extraction",
    "issue_safe_rootfs_ticket",
]
