"""Derived-rootfs follow-up scans with fresh integrity-bound execution tickets.

A firmware ticket authorizes only extraction. It is never reused for downstream tooling. After a
bounded extraction, this module hashes the extracted tree and issues a new ticket for one explicit
local scanner. The tree digest is recomputed immediately before execution, so mutation, symlink
insertion, or substitution invalidates the ticket.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from ..tool_runtime import ToolPin, ToolRuntimeManager
from .asset_cli_executor import (
    CliProcessResult,
    LocalCliExecution,
    Runner,
    execute_local_cli_method,
)
from .asset_deep_capabilities import DeepScannerMethod
from .asset_execution_ticket import (
    AssetExecutionTicket,
    AssetExecutionTicketError,
    _ticket_id,
    verify_offline_execution_ticket,
)
from .asset_normalizers import AssetExecutionObservation, normalize_local_cli_execution
from .safe_archive import SafeArchiveExtraction

ROOTFS_SYFT = DeepScannerMethod(
    "syft",
    "rootfs-sbom",
    ("syft", "dir:{artifact}", "-o", "json"),
    local_only=True,
    output="json",
    purpose="inventory packages and files in a derived firmware rootfs",
)
ROOTFS_GRYPE = DeepScannerMethod(
    "grype",
    "rootfs-vulnerability-scan",
    ("grype", "dir:{artifact}", "-o", "json"),
    local_only=True,
    output="json",
    purpose="match a derived firmware rootfs inventory against known vulnerabilities",
)
ROOTFS_TRIVY = DeepScannerMethod(
    "trivy",
    "rootfs-vulnerability-scan",
    ("trivy", "fs", "--format", "json", "{artifact}"),
    local_only=True,
    output="json",
    purpose="scan a derived firmware rootfs filesystem for package/configuration findings",
)
ROOTFS_METHODS = (ROOTFS_SYFT, ROOTFS_GRYPE, ROOTFS_TRIVY)


class RootfsFollowupError(RuntimeError):
    pass


@dataclass(frozen=True)
class RootfsFollowupOutcome:
    tool: str
    method: str
    candidates: tuple[dict, ...]
    observations: tuple[AssetExecutionObservation, ...]
    provenance: dict
    execution: LocalCliExecution


def _tree_digest(
    root: Path,
    *,
    max_files: int = 20_000,
    max_total_bytes: int = 2 * 1024 * 1024 * 1024,
) -> str:
    if not root.is_dir():
        raise RootfsFollowupError("derived rootfs directory is unavailable")
    rows: list[tuple[str, int, str]] = []
    total = 0
    count = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise RootfsFollowupError("derived rootfs contains a symlink")
        if not path.is_file():
            continue
        count += 1
        if count > max_files:
            raise RootfsFollowupError("derived rootfs exceeds file-count integrity limit")
        size = path.stat().st_size
        total += size
        if total > max_total_bytes:
            raise RootfsFollowupError("derived rootfs exceeds integrity byte limit")
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        rows.append((path.relative_to(root).as_posix(), size, digest.hexdigest()))
    encoded = json.dumps(rows, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _supported(method: DeepScannerMethod) -> bool:
    identity = (str(method.tool), str(method.method))
    return any((str(item.tool), str(item.method)) == identity for item in ROOTFS_METHODS)


def issue_rootfs_followup_ticket(
    extraction: SafeArchiveExtraction,
    method: DeepScannerMethod,
    *,
    scope_digest: str,
) -> AssetExecutionTicket:
    """Issue one scanner ticket bound to the current extracted tree digest."""
    if not _supported(method):
        raise AssetExecutionTicketError("method is not a registered rootfs follow-up")
    scope = str(scope_digest or "").strip()
    if not scope:
        raise AssetExecutionTicketError("scope_digest is required")
    root = Path(extraction.root).resolve()
    digest = _tree_digest(root)
    requirements = ("derived_rootfs", f"source_archive:{extraction.archive_sha256}")
    material = {
        "scope_digest": scope,
        "asset_kind": "firmware_rootfs",
        "tool": str(method.tool),
        "method": str(method.method),
        "requirements": requirements,
        "availability_digest": digest,
        "offline_only": True,
    }
    return AssetExecutionTicket(
        ticket_id=_ticket_id(material),
        scope_digest=scope,
        asset_kind="firmware_rootfs",
        tool=str(method.tool),
        method=str(method.method),
        requirements=requirements,
        availability_digest=digest,
        offline_only=True,
    )


def execute_rootfs_followup(
    extraction: SafeArchiveExtraction,
    method: DeepScannerMethod,
    *,
    ticket: AssetExecutionTicket,
    scope_digest: str,
    workspace_root: str | Path | None = None,
    timeout: float = 300.0,
    runtime_manager: ToolRuntimeManager | None = None,
    pins: dict[str, ToolPin] | None = None,
    runner: Runner | None = None,
) -> RootfsFollowupOutcome:
    """Execute one explicit local scanner only if the derived tree still matches its ticket."""
    if not _supported(method):
        raise RootfsFollowupError("method is not a registered rootfs follow-up")
    try:
        verify_offline_execution_ticket(ticket, method, scope_digest=scope_digest)
    except AssetExecutionTicketError as exc:
        raise RootfsFollowupError(str(exc)) from exc
    if ticket.asset_kind != "firmware_rootfs":
        raise RootfsFollowupError("ticket does not authorize a derived firmware rootfs")
    root = Path(extraction.root).resolve()
    current_digest = _tree_digest(root)
    if current_digest != ticket.availability_digest:
        raise RootfsFollowupError("derived rootfs integrity changed after ticket issuance")

    execution = execute_local_cli_method(
        method,
        artifact_path=root,
        workspace_root=workspace_root,
        timeout=timeout,
        runtime_manager=runtime_manager,
        pins=pins,
        runner=runner,
    )
    normalized = normalize_local_cli_execution(execution)
    provenance = dict(execution.provenance)
    provenance.update(
        {
            "execution_ticket": ticket.ticket_id,
            "scope_digest": ticket.scope_digest,
            "derived_rootfs_digest": current_digest,
            "source_archive_sha256": extraction.archive_sha256,
            "verification_state": "candidate",
        }
    )
    return RootfsFollowupOutcome(
        tool=execution.tool,
        method=execution.method,
        candidates=normalized.candidates,
        observations=normalized.observations,
        provenance=provenance,
        execution=execution,
    )


__all__ = [
    "ROOTFS_GRYPE",
    "ROOTFS_METHODS",
    "ROOTFS_SYFT",
    "ROOTFS_TRIVY",
    "RootfsFollowupError",
    "RootfsFollowupOutcome",
    "execute_rootfs_followup",
    "issue_rootfs_followup_ticket",
    "CliProcessResult",
]
