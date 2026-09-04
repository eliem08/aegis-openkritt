"""Generate the execution backlog from canonical inventory and immutable coverage evidence."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from .runners import backend_runtime_id, runner_profile_for_binary

_EXECUTED = {"EXECUTED_PASS", "EXECUTED_FINDING"}

_CLOSURE_CLASS_BY_RUNNER = {
    "arsenal-linux": ("A", "normal Linux software"),
    "arsenal-network-lab": ("A", "normal Linux software"),
    "arsenal-binary": ("B", "Linux heavy/toolchain"),
    "arsenal-smart-contract": ("B", "Linux heavy/toolchain"),
    "arsenal-android": ("C", "Android"),
    "arsenal-firmware": ("D", "firmware/QEMU"),
    "arsenal-kubernetes": ("E", "Kubernetes"),
    "arsenal-cloud-lab": ("F", "cloud sandbox"),
    "arsenal-macos-ios": ("G", "macOS/iOS"),
    "arsenal-core": ("H", "internal fixture/provider gap"),
    "arsenal-llm": ("H", "internal fixture/provider gap"),
    "arsenal-passive-provider": ("A", "passive provider"),
}


def build_never_executed_backlog(
    inventory: Mapping[str, Any], coverage: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    coverage = coverage or {}
    executions = list(coverage.get("executions", ()))
    by_capability: dict[str, list[Mapping[str, Any]]] = {}
    for item in executions:
        by_capability.setdefault(str(item.get("capability_id", "")), []).append(item)
    reported_never = (
        {str(item) for item in coverage.get("never_executed_backend_ids", ())}
        if "never_executed_backend_ids" in coverage else None
    )

    rows = []
    for backend in inventory.get("backends", ()):
        if not backend.get("external"):
            continue
        backend_id = str(backend.get("backend_id", ""))
        capability_ids = tuple(str(item) for item in backend.get("capability_ids", ()))
        relevant = [row for capability in capability_ids for row in by_capability.get(capability, ())]
        has_execution = any(str(row.get("result")) in _EXECUTED for row in relevant)
        if has_execution and (reported_never is None or backend_id not in reported_never):
            continue
        binary = str(backend.get("binary", ""))
        runtime = dict(backend.get("runtime") or {})
        fixture_capabilities = tuple(backend.get("fixture_executable_capabilities", ()))
        reason = next((
            str(row.get("summary", {}).get("blocking_reason")
                or row.get("summary", {}).get("execution_error_class") or "")
            for row in reversed(relevant)
            if row.get("summary", {}).get("blocking_reason")
            or row.get("summary", {}).get("execution_error_class")
        ), "") or str(runtime.get("reason") or backend.get("prerequisite") or "never executed")
        profile = runner_profile_for_binary(binary)
        state = next((
            str(row.get("result")) for row in reversed(relevant)
            if str(row.get("result")) not in _EXECUTED
        ), str(backend.get("current_state", "UNAVAILABLE")))
        installed = bool(runtime.get("resolved_path")) and runtime.get("status") == "ready"
        missing_fixture = not fixture_capabilities
        missing_executor = not backend.get("executor_providers")
        missing_parser = not any(
            "parser" in str(path).casefold() or "tool_registry" in str(path).casefold()
            for path in backend.get("implementation_paths", ())
        )
        prerequisite = str(backend.get("prerequisite") or "")
        closure_code, closure_name = _CLOSURE_CLASS_BY_RUNNER.get(
            profile, ("H", "internal fixture/provider gap")
        )
        rows.append({
            "backend": backend_id,
            "backend_runtime_id": backend.get("backend_runtime_id") or backend_runtime_id(
                binary, runner_profile=profile,
            ),
            "capability_ids": list(capability_ids),
            "platform": profile,
            "binary": binary,
            "expected_version": list(backend.get("expected_versions", ())),
            "installed_version": str(runtime.get("version") or ""),
            "current_status": state,
            "exact_failure": reason,
            "missing_runtime": not installed,
            "missing_fixture": missing_fixture,
            "missing_parser": missing_parser,
            "missing_executor": missing_executor,
            "missing_privilege": "privileged" in prerequisite.casefold(),
            "required_runner": profile,
            "runner_required": profile,
            "installation_required": not installed,
            "fixture_required": missing_fixture,
            "executor_required": missing_executor,
            "parser_required": missing_parser,
            "privilege_required": "privileged" in prerequisite.casefold(),
            "estimated_closure_class": closure_code,
            "estimated_closure_class_name": closure_name,
            "remediation": _remediation(
                installed=installed, missing_fixture=missing_fixture,
                missing_parser=missing_parser, missing_executor=missing_executor,
                prerequisite=prerequisite, profile=profile,
            ),
        })
    return {
        "schema_version": 2,
        "generated_at": datetime.now(UTC).isoformat(),
        "metrics": {
            "backlog_count": len(rows),
            "missing_runtime_count": sum(row["missing_runtime"] for row in rows),
            "missing_fixture_count": sum(row["missing_fixture"] for row in rows),
            "missing_parser_count": sum(row["missing_parser"] for row in rows),
            "missing_executor_count": sum(row["missing_executor"] for row in rows),
        },
        "backends": sorted(rows, key=lambda row: row["backend_runtime_id"]),
    }


def _remediation(*, installed: bool, missing_fixture: bool, missing_parser: bool,
                 missing_executor: bool, prerequisite: str, profile: str) -> list[str]:
    values = []
    if not installed:
        values.append("install and pin runtime")
    if missing_fixture:
        values.append("add deterministic positive/negative fixture")
    if missing_parser:
        values.append("connect native-output parser")
    if missing_executor:
        values.append("register canonical fixture executor")
    if prerequisite:
        values.append(f"provision {profile}: {prerequisite}")
    return values or ["verify historical evidence and rerun"]


def render_backlog_markdown(document: Mapping[str, Any]) -> str:
    metrics = document["metrics"]
    lines = [
        "# Never-executed arsenal backends", "",
        f"Backlog: **{metrics['backlog_count']}**", "",
        "| Class | Runtime | State | Runner | Version | Failure | Remediation |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in document.get("backends", ()):
        lines.append(
            f"| {row['estimated_closure_class']} | `{row['backend_runtime_id']}` | "
            f"{row['current_status']} | "
            f"`{row['required_runner']}` | `{row['installed_version']}` | "
            f"{row['exact_failure']} | {'; '.join(row['remediation'])} |"
        )
    return "\n".join(lines) + "\n"


def write_backlog(document: Mapping[str, Any], *, json_path: str | Path,
                  markdown_path: str | Path) -> None:
    json_destination = Path(json_path)
    markdown_destination = Path(markdown_path)
    json_destination.parent.mkdir(parents=True, exist_ok=True)
    markdown_destination.parent.mkdir(parents=True, exist_ok=True)
    json_destination.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    markdown_destination.write_text(render_backlog_markdown(document), encoding="utf-8")


__all__ = ["build_never_executed_backlog", "render_backlog_markdown", "write_backlog"]
