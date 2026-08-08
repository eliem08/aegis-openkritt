"""Static-only Solidity pipeline for an authorized single source artifact.

This deliberately does not run Foundry tests, Echidna campaigns, project build hooks, deployment
scripts or RPC forks. A single existing ``.sol`` file is SHA-bound to the normal smart-contract
capability ticket and analyzed by trusted local Slither/Mythril CLIs inside Bubblewrap's unshared
network namespace. Their outputs remain unverified candidates.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from ..tool_runtime import ToolPin, ToolRuntimeManager
from .asset_capabilities import SLITHER, AssetKind, ScannerMethod
from .asset_deep_capabilities import MYTHRIL, DeepScannerMethod
from .asset_execution_ticket import CapabilityAvailability, issue_offline_execution_ticket
from .asset_normalizers import AssetExecutionObservation, normalize_local_cli_execution
from .ticketed_networkless import execute_ticketed_networkless_method


class ContractStaticError(RuntimeError):
    pass


@dataclass(frozen=True)
class ContractStageResult:
    stage: str
    status: str
    detail: str = ""


@dataclass
class ContractStaticReport:
    source_path: str
    source_sha256: str
    scope_digest: str
    stages: list[ContractStageResult] = field(default_factory=list)
    candidates: list[dict] = field(default_factory=list)
    observations: list[AssetExecutionObservation] = field(default_factory=list)
    engine_errors: dict[str, str] = field(default_factory=dict)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_source(path: str | Path, *, max_bytes: int = 10 * 1024 * 1024) -> Path:
    source = Path(path).expanduser().resolve()
    if not source.is_file():
        raise ContractStaticError("Solidity source must be an existing regular file")
    if source.suffix.lower() != ".sol":
        raise ContractStaticError("static contract pipeline accepts one .sol source artifact only")
    size = source.stat().st_size
    if size <= 0 or size > max_bytes:
        raise ContractStaticError("Solidity source size is outside the allowed range")
    return source


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


def _identity(method) -> str:
    return f"{method.tool}/{method.method}"


def run_contract_static_pipeline(
    source_path: str | Path,
    *,
    scope_digest: str,
    methods: Iterable[ScannerMethod | DeepScannerMethod] = (SLITHER, MYTHRIL),
    workspace_root: str | Path | None = None,
    runtime_manager: ToolRuntimeManager | None = None,
    pins: dict[str, ToolPin] | None = None,
    process_runner=None,
) -> ContractStaticReport:
    """Analyze exactly one Solidity file; preserve partial results if one engine is unavailable."""
    source = _validate_source(source_path)
    source_digest = _sha256_file(source)
    report = ContractStaticReport(str(source), source_digest, str(scope_digest))
    rows: list[dict] = []
    availability = CapabilityAvailability(artifact_available=True)

    for method in tuple(methods):
        identity = _identity(method)
        try:
            ticket = issue_offline_execution_ticket(
                asset_kind=AssetKind.SMART_CONTRACT,
                method=method,
                scope_digest=scope_digest,
                availability=availability,
            )
            # The base planner ticket proves an authorized artifact exists. Bind this run to the
            # actual file hash in provenance and re-check it immediately before each engine.
            if _sha256_file(source) != source_digest:
                raise ContractStaticError("Solidity source changed during the analysis run")
            execution = execute_ticketed_networkless_method(
                method,
                ticket=ticket,
                scope_digest=scope_digest,
                artifact_path=source,
                workspace_root=workspace_root,
                runtime_manager=runtime_manager,
                pins=pins,
                process_runner=process_runner,
            )
            if _sha256_file(source) != source_digest:
                raise ContractStaticError("Solidity source changed after scanner execution")
            normalized = normalize_local_cli_execution(execution)
            for candidate in normalized.candidates:
                candidate.setdefault("contract_artifact", {})["sha256"] = source_digest
            rows.extend(normalized.candidates)
            report.observations.extend(normalized.observations)
            report.stages.append(ContractStageResult(identity, "complete"))
        except Exception as exc:
            report.engine_errors[identity] = f"{type(exc).__name__}: {exc}"[:240]
            report.stages.append(ContractStageResult(identity, "failed", report.engine_errors[identity]))

    report.candidates = _dedupe(rows)
    return report
