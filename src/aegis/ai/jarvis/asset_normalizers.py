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
_MODEL_SCAN_SEVERITIES = {"critical", "high", "medium", "low"}
_SENSITIVE_FIELD_PARTS = ("secret", "token", "password", "credential", "private_key")


def _safe_text(value: Any, limit: int = 1000) -> str:
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return ""
    return str(value).replace("\x00", " ").replace("\r", " ").replace("\n", " ").strip()[:limit]


def _modelscan_issue(node: dict[str, Any]) -> dict | None:
    lowered = {str(key).lower(): value for key, value in node.items()}
    severity = _safe_text(lowered.get("severity"), 30).lower()
    if severity not in _MODEL_SCAN_SEVERITIES:
        return None
    description = _safe_text(lowered.get("description"), 1600)
    operator = _safe_text(lowered.get("operator"), 300)
    module = _safe_text(lowered.get("module"), 200)
    source = _safe_text(lowered.get("source"), 500)
    scanner = _safe_text(lowered.get("scanner"), 160)
    if not (description or operator) or not (source or scanner or module):
        return None
    summary = description or f"Unsafe model operator {operator}"
    if operator and operator.lower() not in summary.lower():
        summary = f"{summary} ({operator})"
    weakness = "Model serialization unsafe operator"
    if operator:
        weakness = f"ModelScan unsafe operator: {operator}"[:200]
    return {
        "json_answer": {
            "vulnerability_type": weakness,
            "file_path": source,
            "line": 0,
            "summary": summary[:300],
            "explanation": description[:1600],
        },
        "severity": severity,
        "source": "aegis:tool:modelscan",
        "confidence": 0.7 if severity in {"critical", "high"} else 0.6,
        "scanner_metadata": {
            "scanner": scanner or None,
            "module": module or None,
            "operator": operator or None,
            "validation": "modelscan-static-candidate",
            "model_deserialized": False,
        },
    }


def _parse_modelscan(payload: dict | list) -> list[dict]:
    """Tolerate ModelScan report wrappers while only accepting its issue-detail contract."""
    rows: list[dict] = []

    def walk(value: Any) -> None:
        if isinstance(value, list):
            for item in value[:10000]:
                walk(item)
            return
        if not isinstance(value, dict):
            return
        issue = _modelscan_issue(value)
        if issue is not None:
            rows.append(issue)
            return
        for key, child in value.items():
            if any(part in str(key).lower() for part in _SENSITIVE_FIELD_PARTS):
                continue
            if isinstance(child, (dict, list)):
                walk(child)

    walk(payload)
    output: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        answer = row.get("json_answer") or {}
        key = (
            str(answer.get("file_path") or ""),
            str((row.get("scanner_metadata") or {}).get("operator") or ""),
            str(answer.get("summary") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(row)
    return output


_PARSERS: dict[str, Parser] = {
    "bandit": registry._parse_bandit,
    "brakeman": registry._parse_brakeman,
    "checkov": registry._parse_checkov,
    "gosec": registry._parse_gosec,
    "grype": registry._parse_grype,
    "modelscan": _parse_modelscan,
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


def _successful_scan(execution: LocalCliExecution, key: str) -> bool:
    if execution.timed_out:
        return False
    if key == "modelscan":
        return execution.returncode in {0, 1}
    return execution.returncode == 0


def normalize_local_cli_execution(execution: LocalCliExecution) -> NormalizedAssetExecution:
    """Normalize one local execution into candidates and/or non-finding observations."""
    payload = _json_payload(execution)
    key = execution.tool.strip().lower()
    parser = _PARSERS.get(key)
    successful = _successful_scan(execution, key)
    if parser is not None and payload is not None and successful:
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
                        "successful_scan": successful,
                        "timed_out": execution.timed_out,
                        "candidate_count": len(rows),
                        "runtime": _safe_runtime(execution),
                    },
                ),
            ),
        )

    if key == "syft" and successful:
        data = _sbom_observation(payload, execution)
        kind = "sbom_inventory"
    else:
        data = {
            "returncode": execution.returncode,
            "successful_scan": successful,
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
            "normalizer": (
                "no-vulnerability-parser-registered" if successful
                else "execution-not-successful"
            ),
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
