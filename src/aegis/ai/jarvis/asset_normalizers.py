"""Normalize guarded asset CLI executions without duplicating scanner schemas.

Where Aegis already has a deterministic parser in ``tool_registry``, this module reuses it.
Extraction/inventory tools that do not directly assert vulnerabilities become observations rather
than fabricated findings. Every candidate receives the exact runtime provenance from the local
executor and stays ``unverified`` until the normal evidence lifecycle promotes it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

from .. import tool_registry as registry
from .asset_cli_executor import LocalCliExecution

Parser = Callable[[dict | list], list[dict]]

_PARSERS: dict[str, Parser] = {
    "bandit": registry._parse_bandit,
    "brakeman": registry._parse_brakeman,
    "checkov": registry._parse_checkov,
    "gosec": registry._parse_gosec,
    "grype": registry._parse_grype,
    "mythril": registry._parse_mythril,
    "osv-scanner": registry._parse_osv,
    "osv-scanner image": registry._parse_osv,
    "psalm": registry._parse_psalm,
    "slither": registry._parse_slither,
    "trivy": registry._parse_trivy,
    "trivy image": registry._parse_trivy,
}


@dataclass(frozen=True)
class AssetExecutionObservation:
    kind: str
    tool: str
    method: str
    data: dict[str, Any]


@dataclass(frozen=True)
class NormalizedAssetExecution:
    candidates: tuple[dict, ...]
    observations: tuple[AssetExecutionObservation, ...]


def _json_payload(execution: LocalCliExecution) -> dict | list | None:
    raw = execution.output_file or execution.raw_stdout
    if not raw:
        return None
    try:
        payload = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, (dict, list)) else None


def _safe_runtime(execution: LocalCliExecution) -> dict:
    provenance = dict(execution.provenance)
    # argv may contain local checkout paths; useful for an internal artifact ledger but noisy in
    # a finding row. Retain exact argv in executor provenance and keep a compact candidate copy.
    return {
        "tool": provenance.get("tool"),
        "status": provenance.get("status"),
        "version": provenance.get("version"),
        "binary_sha256": provenance.get("binary_sha256"),
        "execution_mode": provenance.get("execution_mode"),
        "shell": provenance.get("shell"),
    }


def _candidate_provenance(execution: LocalCliExecution) -> dict:
    return {
        "method": execution.method,
        "returncode": execution.returncode,
        "timed_out": execution.timed_out,
        "stdout_sha256": execution.stdout_sha256,
        "stderr_sha256": execution.stderr_sha256,
        "output_files": len(execution.outputs),
    }


def _attach_provenance(rows: list[dict], execution: LocalCliExecution) -> tuple[dict, ...]:
    runtime = _safe_runtime(execution)
    asset_execution = _candidate_provenance(execution)
    output: list[dict] = []
    for source_row in rows:
        row = dict(source_row)
        row["validation_status"] = "unverified"
        row["scanner_runtime"] = runtime
        row["asset_execution"] = asset_execution
        output.append(row)
    return tuple(output)


def _sbom_observation(payload: dict | list | None, execution: LocalCliExecution) -> dict[str, Any]:
    packages = 0
    artifacts = 0
    if isinstance(payload, dict):
        package_values = payload.get("artifacts") or payload.get("packages") or []
        if isinstance(package_values, list):
            packages = len(package_values)
        source = payload.get("source")
        if isinstance(source, dict):
            artifacts = 1
    return {
        "packages": packages,
        "sources": artifacts,
        "stdout_sha256": execution.stdout_sha256,
        "output_files": len(execution.outputs),
    }


def normalize_local_cli_execution(execution: LocalCliExecution) -> NormalizedAssetExecution:
    """Normalize one local execution into candidates and/or non-finding observations."""
    payload = _json_payload(execution)
    key = execution.tool.strip().lower()
    parser = _PARSERS.get(key)
    if parser is not None and payload is not None:
        try:
            rows = parser(payload)
        except Exception:
            rows = []
        return NormalizedAssetExecution(
            candidates=_attach_provenance(rows, execution),
            observations=(
                AssetExecutionObservation(
                    kind="scanner_run",
                    tool=execution.tool,
                    method=execution.method,
                    data={
                        "returncode": execution.returncode,
                        "timed_out": execution.timed_out,
                        "candidate_count": len(rows),
                        "runtime": _safe_runtime(execution),
                    },
                ),
            ),
        )

    if key == "syft":
        data = _sbom_observation(payload, execution)
        kind = "sbom_inventory"
    else:
        data = {
            "returncode": execution.returncode,
            "timed_out": execution.timed_out,
            "stdout_sha256": execution.stdout_sha256,
            "stderr_sha256": execution.stderr_sha256,
            "outputs": [
                {
                    "path": item.relative_path,
                    "size_bytes": item.size_bytes,
                    "sha256": item.sha256,
                }
                for item in execution.outputs[:100]
            ],
            "runtime": _safe_runtime(execution),
            "normalizer": "no-vulnerability-parser-registered",
        }
        kind = "tool_observation"

    return NormalizedAssetExecution(
        candidates=(),
        observations=(
            AssetExecutionObservation(
                kind=kind,
                tool=execution.tool,
                method=execution.method,
                data=data,
            ),
        ),
    )
