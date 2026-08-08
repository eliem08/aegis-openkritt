"""Safe offline native-binary research pipeline.

The pipeline never executes the target binary. It combines:
- deterministic PE/ELF header/mitigation metadata;
- kernel-networkless trusted scanner CLIs (capa, Syft, Grype);
- optional Ghidra headless analysis through the dedicated Bubblewrap sandbox backend.

Scanner findings remain candidates/observations; no output is promoted past the normal Aegis
evidence lifecycle here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from ..tool_runtime import ToolPin, ToolRuntimeManager
from .asset_capabilities import CAPA, GRYPE, SYFT, AssetKind, ScannerMethod
from .asset_deep_capabilities import GHIDRA
from .asset_execution_ticket import CapabilityAvailability, issue_offline_execution_ticket
from .asset_normalizers import AssetExecutionObservation, normalize_local_cli_execution
from .binary_metadata import BinaryMetadataError, analyze_binary_metadata
from .ghidra_sandbox import execute_ghidra_sandboxed
from .ticketed_networkless import execute_ticketed_networkless_method


@dataclass(frozen=True)
class BinaryStageResult:
    stage: str
    status: str
    detail: str = ""


@dataclass
class BinaryPipelineReport:
    binary_path: str
    scope_digest: str
    stages: list[BinaryStageResult] = field(default_factory=list)
    candidates: list[dict] = field(default_factory=list)
    observations: list[AssetExecutionObservation] = field(default_factory=list)
    engine_errors: dict[str, str] = field(default_factory=dict)


def _dedupe(rows: Iterable[dict]) -> list[dict]:
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


def _scanner_identity(method) -> str:
    return f"{method.tool}/{method.method}"


def run_binary_offline_pipeline(
    binary_path: str | Path,
    *,
    scope_digest: str,
    scanner_methods: Iterable[ScannerMethod] = (CAPA, SYFT, GRYPE),
    include_ghidra: bool = False,
    sandbox_available: bool = False,
    workspace_root: str | Path | None = None,
    runtime_manager: ToolRuntimeManager | None = None,
    pins: dict[str, ToolPin] | None = None,
    process_runner=None,
    ghidra_runner=None,
) -> BinaryPipelineReport:
    """Run independent native-binary lanes while preserving partial results."""
    binary = Path(binary_path).expanduser().resolve()
    report = BinaryPipelineReport(str(binary), str(scope_digest))
    candidates: list[dict] = []

    try:
        metadata = analyze_binary_metadata(binary)
        candidates.extend(metadata.candidates)
        report.observations.append(
            AssetExecutionObservation(
                kind="binary_metadata",
                tool="aegis-binary-metadata",
                method="pe-elf-header-analysis",
                data={
                    "file_name": metadata.file_name,
                    "size_bytes": metadata.size_bytes,
                    "sha256": metadata.sha256,
                    "format": metadata.format,
                    "architecture": metadata.architecture,
                    "bits": metadata.bits,
                    "endianness": metadata.endianness,
                    "image_type": metadata.image_type,
                    "mitigations": metadata.mitigations,
                    "details": metadata.details,
                    "verification_state": "observation",
                },
            )
        )
        report.stages.append(BinaryStageResult("metadata", "complete"))
    except BinaryMetadataError as exc:
        report.engine_errors["metadata"] = str(exc)[:240]
        report.stages.append(BinaryStageResult("metadata", "failed", str(exc)[:240]))
        return report

    availability = CapabilityAvailability(artifact_available=True)
    for method in tuple(scanner_methods):
        identity = _scanner_identity(method)
        try:
            ticket = issue_offline_execution_ticket(
                asset_kind=AssetKind.EXECUTABLE,
                method=method,
                scope_digest=scope_digest,
                availability=availability,
            )
            execution = execute_ticketed_networkless_method(
                method,
                ticket=ticket,
                scope_digest=scope_digest,
                artifact_path=binary,
                workspace_root=workspace_root,
                runtime_manager=runtime_manager,
                pins=pins,
                process_runner=process_runner,
            )
            normalized = normalize_local_cli_execution(execution)
            candidates.extend(normalized.candidates)
            report.observations.extend(normalized.observations)
            report.stages.append(BinaryStageResult(identity, "complete"))
        except Exception as exc:
            report.engine_errors[identity] = f"{type(exc).__name__}: {exc}"[:240]
            report.stages.append(BinaryStageResult(identity, "failed", report.engine_errors[identity]))

    if include_ghidra:
        identity = _scanner_identity(GHIDRA)
        try:
            ticket = issue_offline_execution_ticket(
                asset_kind=AssetKind.EXECUTABLE,
                method=GHIDRA,
                scope_digest=scope_digest,
                availability=CapabilityAvailability(
                    artifact_available=True,
                    sandbox_available=sandbox_available,
                ),
            )
            execution = execute_ghidra_sandboxed(
                artifact_path=binary,
                ticket=ticket,
                workspace_root=workspace_root,
                runtime_manager=runtime_manager,
                pins=pins,
                runner=ghidra_runner,
            )
            report.observations.append(
                AssetExecutionObservation(
                    kind="binary_analysis",
                    tool="Ghidra",
                    method=GHIDRA.method,
                    data={
                        "returncode": execution.returncode,
                        "timed_out": execution.timed_out,
                        "analysis_log_sha256": execution.analysis_log_sha256,
                        "analysis_log_size": execution.analysis_log_size,
                        "sandbox": execution.provenance.get("sandbox"),
                        "verification_state": "observation",
                    },
                )
            )
            report.stages.append(BinaryStageResult(identity, "complete"))
        except Exception as exc:
            report.engine_errors[identity] = f"{type(exc).__name__}: {exc}"[:240]
            report.stages.append(BinaryStageResult(identity, "failed", report.engine_errors[identity]))

    report.candidates = _dedupe(candidates)
    return report
