"""Safe offline firmware research pipeline.

Pipeline stages are deliberately monotonic and local:

1. deterministic firmware metadata/architecture observation,
2. bounded ZIP/plain-TAR extraction when supported,
3. extracted web/config/service surface correlation,
4. fresh integrity-bound tickets for selected rootfs Syft/Grype/Trivy follow-ups,
5. candidate deduplication and workspace cleanup.

Unsupported raw filesystems stop with an explicit backend requirement. No emulation, mount,
network access, binary execution, or vulnerability confirmation occurs in this pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from ..tool_runtime import ToolPin, ToolRuntimeManager
from .asset_capabilities import AssetKind
from .asset_deep_capabilities import ARCH_DETECT, DeepScannerMethod
from .asset_execution import execute_authorized_offline_method
from .asset_execution_ticket import CapabilityAvailability, issue_offline_execution_ticket
from .asset_normalizers import AssetExecutionObservation
from .firmware_execution import (
    FirmwareExecutionError,
    cleanup_safe_archive,
    execute_safe_rootfs_extraction,
    issue_safe_rootfs_ticket,
)
from .rootfs_followup import (
    ROOTFS_METHODS,
    RootfsFollowupError,
    execute_rootfs_followup,
    issue_rootfs_followup_ticket,
)
from .rootfs_surface import RootfsSurfaceError, correlate_rootfs_surface
from .safe_archive import SafeArchiveExtraction, SafeArchiveLimits


@dataclass(frozen=True)
class FirmwareStageResult:
    stage: str
    status: str
    detail: str = ""
    observations: tuple[AssetExecutionObservation, ...] = ()


@dataclass
class FirmwarePipelineReport:
    firmware_path: str
    scope_digest: str
    stages: list[FirmwareStageResult] = field(default_factory=list)
    candidates: list[dict] = field(default_factory=list)
    observations: list[AssetExecutionObservation] = field(default_factory=list)
    followup_tools: list[str] = field(default_factory=list)
    followup_errors: dict[str, str] = field(default_factory=dict)
    needs_isolated_filesystem_backend: bool = False
    rootfs_retained: bool = False
    rootfs_path: str = ""

    def add_stage(self, result: FirmwareStageResult) -> None:
        self.stages.append(result)
        self.observations.extend(result.observations)


def _dedupe_candidates(rows: Iterable[dict]) -> list[dict]:
    output: list[dict] = []
    seen: set[tuple[str, str, int, str]] = set()
    for row in rows:
        answer = row.get("json_answer") or {}
        key = (
            str(answer.get("vulnerability_type") or row.get("cwe") or ""),
            str(answer.get("file_path") or ""),
            int(answer.get("line") or 0),
            str(answer.get("summary") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(row)
    return output


def run_firmware_offline_pipeline(
    firmware_path: str | Path,
    *,
    scope_digest: str,
    followup_methods: Iterable[DeepScannerMethod] = ROOTFS_METHODS,
    workspace_root: str | Path | None = None,
    retain_rootfs: bool = False,
    extraction_limits: SafeArchiveLimits | None = None,
    runtime_manager: ToolRuntimeManager | None = None,
    pins: dict[str, ToolPin] | None = None,
    runner=None,
) -> FirmwarePipelineReport:
    """Run the safe offline firmware chain; scanner availability failures are recorded, not hidden."""
    firmware = Path(firmware_path).expanduser().resolve()
    report = FirmwarePipelineReport(str(firmware), str(scope_digest))
    availability = CapabilityAvailability(firmware_available=True)

    # Stage 1: deterministic bytes-only metadata through the normal asset ticket/router path.
    try:
        metadata_ticket = issue_offline_execution_ticket(
            asset_kind=AssetKind.HARDWARE,
            method=ARCH_DETECT,
            scope_digest=scope_digest,
            availability=availability,
        )
        metadata = execute_authorized_offline_method(
            ARCH_DETECT,
            ticket=metadata_ticket,
            scope_digest=scope_digest,
            firmware_path=firmware,
        )
        report.add_stage(
            FirmwareStageResult(
                "metadata",
                "complete",
                observations=metadata.observations,
            )
        )
    except Exception as exc:
        report.add_stage(
            FirmwareStageResult("metadata", "failed", f"{type(exc).__name__}: {exc}"[:240])
        )
        return report

    extraction: SafeArchiveExtraction | None = None
    try:
        extraction_ticket = issue_safe_rootfs_ticket(
            scope_digest=scope_digest,
            availability=availability,
        )
        extracted = execute_safe_rootfs_extraction(
            ticket=extraction_ticket,
            scope_digest=scope_digest,
            firmware_path=firmware,
            workspace_root=workspace_root,
            limits=extraction_limits,
        )
        extraction = extracted.extraction
        report.add_stage(
            FirmwareStageResult(
                "extract",
                "complete",
                observations=extracted.observations,
            )
        )
    except FirmwareExecutionError as exc:
        report.needs_isolated_filesystem_backend = True
        report.add_stage(FirmwareStageResult("extract", "unsupported", str(exc)[:240]))
        return report

    try:
        surface = correlate_rootfs_surface(extraction)
        surface_observation = AssetExecutionObservation(
            kind="rootfs_surface",
            tool="aegis-rootfs-surface",
            method="offline-surface-correlation",
            data=surface.as_dict(),
        )
        report.add_stage(
            FirmwareStageResult("surface", "complete", observations=(surface_observation,))
        )

        followup_candidates: list[dict] = []
        followup_observations: list[AssetExecutionObservation] = []
        for method in tuple(followup_methods):
            identity = f"{method.tool}/{method.method}"
            try:
                ticket = issue_rootfs_followup_ticket(
                    extraction,
                    method,
                    scope_digest=scope_digest,
                )
                outcome = execute_rootfs_followup(
                    extraction,
                    method,
                    ticket=ticket,
                    scope_digest=scope_digest,
                    workspace_root=workspace_root,
                    runtime_manager=runtime_manager,
                    pins=pins,
                    runner=runner,
                )
                report.followup_tools.append(identity)
                followup_candidates.extend(outcome.candidates)
                followup_observations.extend(outcome.observations)
            except RootfsFollowupError as exc:
                report.followup_errors[identity] = str(exc)[:240]
            except Exception as exc:
                report.followup_errors[identity] = f"{type(exc).__name__}: {exc}"[:240]
        report.candidates = _dedupe_candidates(followup_candidates)
        report.add_stage(
            FirmwareStageResult(
                "rootfs_followups",
                "complete" if not report.followup_errors else "partial",
                detail=(
                    f"{len(report.followup_tools)} completed, "
                    f"{len(report.followup_errors)} unavailable/failed"
                ),
                observations=tuple(followup_observations),
            )
        )
    except RootfsSurfaceError as exc:
        report.add_stage(FirmwareStageResult("surface", "failed", str(exc)[:240]))
    finally:
        if extraction is not None:
            if retain_rootfs:
                report.rootfs_retained = True
                report.rootfs_path = extraction.root
            else:
                cleanup_safe_archive(extraction)

    return report
