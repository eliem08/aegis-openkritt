"""Safe local AI-model artifact pipeline.

The pipeline never loads/deserializes the model. It first performs bounded structural provenance
inspection, then optionally runs the trusted ModelScan CLI inside the ticketed Bubblewrap
networkless backend. ModelScan output remains unverified candidate evidence.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from ..tool_runtime import ToolPin, ToolRuntimeManager
from .asset_deep_capabilities import DeepScannerMethod
from .asset_execution_ticket import AssetExecutionTicket, _ticket_id
from .asset_normalizers import AssetExecutionObservation, normalize_local_cli_execution
from .model_provenance import (
    ModelArtifactTicket,
    ModelProvenanceError,
    ModelProvenanceReport,
    inspect_model_provenance,
    issue_model_artifact_ticket,
)
from .ticketed_networkless import execute_ticketed_networkless_method


MODEL_SCAN_CLI = DeepScannerMethod(
    "ModelScan",
    "artifact-scan",
    ("modelscan", "-p", "{artifact}", "-r", "json", "-o", "{output}"),
    local_only=True,
    output="json",
    purpose="scan a local model artifact for unsafe serialized operators without loading it",
)


@dataclass(frozen=True)
class AIModelStageResult:
    stage: str
    status: str
    detail: str = ""


@dataclass
class AIModelPipelineReport:
    artifact_path: str
    scope_digest: str
    artifact_ticket: ModelArtifactTicket | None = None
    provenance: ModelProvenanceReport | None = None
    stages: list[AIModelStageResult] = field(default_factory=list)
    candidates: list[dict] = field(default_factory=list)
    observations: list[AssetExecutionObservation] = field(default_factory=list)
    engine_errors: dict[str, str] = field(default_factory=dict)


def _modelscan_ticket(
    artifact_ticket: ModelArtifactTicket,
    *,
    scope_digest: str,
) -> AssetExecutionTicket:
    scope = str(scope_digest or "").strip()
    if artifact_ticket.scope_digest != scope:
        raise ModelProvenanceError("model artifact ticket scope digest mismatch")
    requirements = (
        "authorized_artifact",
        f"model_sha256:{artifact_ticket.sha256}",
        "non_deserializing_scan",
    )
    material = {
        "scope_digest": scope,
        "asset_kind": "ai_model",
        "tool": MODEL_SCAN_CLI.tool,
        "method": MODEL_SCAN_CLI.method,
        "requirements": requirements,
        "availability_digest": artifact_ticket.sha256,
        "offline_only": True,
    }
    return AssetExecutionTicket(
        ticket_id=_ticket_id(material),
        scope_digest=scope,
        asset_kind="ai_model",
        tool=MODEL_SCAN_CLI.tool,
        method=MODEL_SCAN_CLI.method,
        requirements=requirements,
        availability_digest=artifact_ticket.sha256,
        offline_only=True,
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def run_ai_model_pipeline(
    artifact_path: str | Path,
    *,
    scope_digest: str,
    run_modelscan: bool = True,
    workspace_root: str | Path | None = None,
    runtime_manager: ToolRuntimeManager | None = None,
    pins: dict[str, ToolPin] | None = None,
    process_runner=None,
) -> AIModelPipelineReport:
    """Inspect one local model artifact and preserve partial ModelScan failures."""
    artifact = Path(artifact_path).expanduser().resolve()
    report = AIModelPipelineReport(str(artifact), str(scope_digest))
    try:
        artifact_ticket = issue_model_artifact_ticket(artifact, scope_digest=scope_digest)
        provenance = inspect_model_provenance(
            artifact,
            ticket=artifact_ticket,
            scope_digest=scope_digest,
        )
        report.artifact_ticket = artifact_ticket
        report.provenance = provenance
        report.observations.append(
            AssetExecutionObservation(
                kind="ai_model_provenance",
                tool="aegis-model-provenance",
                method="non-deserializing-format-inspection",
                data={
                    "file_name": provenance.file_name,
                    "size_bytes": provenance.size_bytes,
                    "sha256": provenance.sha256,
                    "format": provenance.format,
                    "format_confidence": provenance.format_confidence,
                    "metadata_keys": provenance.metadata_keys,
                    "tensor_headers": tuple(
                        {
                            "name": tensor.name,
                            "dtype": tensor.dtype,
                            "shape": tensor.shape,
                            "data_start": tensor.data_start,
                            "data_end": tensor.data_end,
                        }
                        for tensor in provenance.tensor_headers[:2000]
                    ),
                    "archive_entries": provenance.archive_entries,
                    "archive_uncompressed_bytes": provenance.archive_uncompressed_bytes,
                    "archive_names": provenance.archive_names,
                    "structural_flags": provenance.structural_flags,
                    "deserialized": False,
                    "verification_state": "observation",
                },
            )
        )
        report.stages.append(AIModelStageResult("provenance", "complete"))
    except Exception as exc:
        report.engine_errors["provenance"] = f"{type(exc).__name__}: {exc}"[:240]
        report.stages.append(
            AIModelStageResult("provenance", "failed", report.engine_errors["provenance"])
        )
        return report

    if not run_modelscan:
        report.stages.append(AIModelStageResult("modelscan", "skipped", "disabled by caller"))
        return report

    try:
        # Rebind immediately before scanner execution. A changed model never reaches ModelScan.
        current_digest = _sha256_file(artifact)
        if current_digest != report.artifact_ticket.sha256:
            raise ModelProvenanceError("model artifact changed after provenance inspection")
        ticket = _modelscan_ticket(report.artifact_ticket, scope_digest=scope_digest)
        execution = execute_ticketed_networkless_method(
            MODEL_SCAN_CLI,
            ticket=ticket,
            scope_digest=scope_digest,
            artifact_path=artifact,
            workspace_root=workspace_root,
            runtime_manager=runtime_manager,
            pins=pins,
            process_runner=process_runner,
        )
        if _sha256_file(artifact) != report.artifact_ticket.sha256:
            raise ModelProvenanceError("model artifact changed during ModelScan execution")
        normalized = normalize_local_cli_execution(execution)
        for candidate in normalized.candidates:
            candidate.setdefault("model_artifact", {}).update(
                {
                    "sha256": report.artifact_ticket.sha256,
                    "format": report.provenance.format,
                    "deserialized": False,
                }
            )
        report.candidates.extend(normalized.candidates)
        report.observations.extend(normalized.observations)
        successful = not execution.timed_out and execution.returncode in {0, 1}
        if not successful:
            raise ModelProvenanceError(
                f"ModelScan returned unsuccessful exit code {execution.returncode}"
            )
        report.stages.append(AIModelStageResult("modelscan", "complete"))
    except Exception as exc:
        report.engine_errors["modelscan"] = f"{type(exc).__name__}: {exc}"[:240]
        report.stages.append(
            AIModelStageResult("modelscan", "failed", report.engine_errors["modelscan"])
        )
    return report
