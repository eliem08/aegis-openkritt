"""Evidence-backed backend inventory, tool lock, and fixture coverage reports."""

from __future__ import annotations

import json
import os
import platform
import subprocess
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

from aegis.ai.tool_runtime import ToolRuntimeManager, ToolRuntimeStatus

from .models import ArsenalAuditReport, ArsenalCoverageState, CapabilityDefinition

_INTERNAL_PREFIXES = ("aegis-", "stdlib-")
_BINARY_ALIASES = {
    "electron-asar": "asar",
    "foundry": "forge",
    "ghidra": "analyzeHeadless",
    "mythril": "myth",
    "roadtools": "roadrecon",
    "scoutsuite": "scout",
    "testssl-sh": "testssl.sh",
}
_PREREQUISITES = {
    "class-dump": "macOS worker; readiness: command -v class-dump && uname -s | grep Darwin",
    "firmadyne": (
        "opt-in privileged Linux worker with QEMU/binfmt; readiness: "
        "test -e /dev/kvm && command -v qemu-system-x86_64"
    ),
    "firmae": (
        "opt-in privileged Linux worker with FirmAE/QEMU/binfmt; readiness: "
        "test -e /dev/kvm && command -v qemu-system-x86_64 && test -d /opt/FirmAE"
    ),
    "frida": (
        "operator-owned local emulator/device and fixture app; readiness: "
        "adb devices && frida-ps -U"
    ),
    "mobsf": (
        "loopback MobSF service and synthetic APK; readiness: "
        "test -n \"$AEGIS_MOBSF_URL\" && curl -fsS \"$AEGIS_MOBSF_URL/api/v1/scans\""
    ),
    "objection": (
        "Frida-capable operator-owned emulator/device; readiness: "
        "adb devices && frida-ps -U && objection --version"
    ),
    "otool": "macOS worker; readiness: command -v otool && uname -s | grep Darwin",
    "prowler": "local cloud emulator or explicitly supplied controlled cloud account",
    "roadrecon": "local Entra fixture or explicitly supplied controlled tenant",
    "scout": "local cloud emulator or explicitly supplied controlled cloud account",
    "scoutsuite": "local cloud emulator or explicitly supplied controlled cloud account",
    "azurehound": "local Entra fixture or explicitly supplied controlled tenant",
}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def canonical_binary(binary: str) -> str:
    value = str(binary or "").strip().casefold()
    return _BINARY_ALIASES.get(value, value)


def backend_prerequisite(binary: str) -> str:
    return _PREREQUISITES.get(canonical_binary(binary), "")


def _is_external(binary: str) -> bool:
    value = canonical_binary(binary)
    return bool(value) and not value.startswith(_INTERNAL_PREFIXES) and value != "crt.sh"


def _git_sha() -> str:
    configured = os.environ.get("AEGIS_GIT_SHA", "").strip()
    if configured:
        return configured
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True,
            check=True, timeout=5,
        ).stdout.strip()
    except Exception:
        return ""


def build_backend_inventory(
    report: ArsenalAuditReport,
    *,
    runtime_manager: ToolRuntimeManager | None = None,
) -> dict[str, Any]:
    """Group capabilities by the actual executable/service backend they share."""
    manager = runtime_manager or ToolRuntimeManager(version_timeout=15.0)
    grouped: dict[str, list[tuple[CapabilityDefinition, Any]]] = defaultdict(list)
    internal: dict[str, list[tuple[CapabilityDefinition, Any]]] = defaultdict(list)
    for definition in report.definitions:
        for backend in definition.tool_backends:
            binary = canonical_binary(backend.binary)
            (grouped if _is_external(binary) else internal)[binary or backend.backend_id].append(
                (definition, backend)
            )

    rows: list[dict[str, Any]] = []
    for external, groups in ((True, grouped), (False, internal)):
        for binary, claims in sorted(groups.items()):
            definitions = [item[0] for item in claims]
            backends = [item[1] for item in claims]
            prerequisite = backend_prerequisite(binary)
            if external:
                runtime = manager.inspect(
                    name=sorted({item.tool_name for item in backends})[0],
                    binary=binary,
                    refresh=True,
                )
                if runtime.status is ToolRuntimeStatus.READY:
                    state = ArsenalCoverageState.WAITING_FOR_PREREQUISITE
                elif prerequisite:
                    state = ArsenalCoverageState.WAITING_FOR_PREREQUISITE
                elif runtime.status in {ToolRuntimeStatus.STALE, ToolRuntimeStatus.QUARANTINED}:
                    state = ArsenalCoverageState.BACKEND_UNHEALTHY
                else:
                    state = ArsenalCoverageState.UNAVAILABLE
                runtime_document = runtime.as_dict()
            else:
                state = ArsenalCoverageState.WAITING_FOR_PREREQUISITE
                runtime_document = {
                    "name": sorted({item.tool_name for item in backends})[0],
                    "binary": binary,
                    "resolved_path": "internal-adapter",
                    "version": "aegis-internal",
                    "sha256": "",
                    "status": "internal",
                    "reason": "internal adapter; external binary health is not applicable",
                    "checked_at": _now(),
                }
            capability_ids = sorted({item.capability_id for item in definitions})
            rows.append({
                "backend_id": f"{'external' if external else 'internal'}:{binary}",
                "external": external,
                "binary": binary,
                "tool_names": sorted({item.tool_name for item in backends}),
                "capability_ids": capability_ids,
                "capability_count": len(capability_ids),
                "asset_classes": sorted({
                    asset for item in definitions for asset in item.supported_asset_classes
                }),
                "executor_providers": sorted({
                    item.executor_provider for item in definitions if item.executor_provider
                }),
                "fixture_providers": sorted({
                    item.fixture_provider for item in definitions if item.fixture_provider
                }),
                "fixture_executable_capabilities": sorted({
                    item.capability_id for item in definitions if item.fixture_executable
                }),
                "source_registries": sorted({
                    source for item in definitions for source in item.source_registries
                }),
                "implementation_paths": sorted({
                    path for item in definitions for path in item.implementation_paths
                }),
                "expected_versions": sorted({
                    item.expected_version for item in backends if item.expected_version
                }),
                "adapter_versions": sorted({
                    item.adapter_version for item in backends if item.adapter_version
                }),
                "current_state": state.value,
                "prerequisite": prerequisite,
                "runtime": runtime_document,
                "architecture": platform.machine(),
                "installation_source": "resolved executable/runtime probe" if external else "Aegis",
            })
    external_rows = [item for item in rows if item["external"]]
    return {
        "schema_version": 1,
        "generated_at": _now(),
        "git_sha": _git_sha(),
        "metrics": {
            "canonical_capability_count": len(report.definitions),
            "unique_backend_count": len(rows),
            "unique_external_backend_count": len(external_rows),
            "unique_internal_backend_count": len(rows) - len(external_rows),
            "installed_external_backend_count": sum(
                item["runtime"]["status"] == ToolRuntimeStatus.READY.value
                for item in external_rows
            ),
        },
        "backends": sorted(rows, key=lambda item: item["backend_id"]),
    }


def build_tool_lock(inventory: Mapping[str, Any], *, image_digest: str = "") -> dict[str, Any]:
    tools = []
    for backend in inventory.get("backends", []):
        if not backend.get("external"):
            continue
        runtime = dict(backend.get("runtime") or {})
        if not runtime.get("resolved_path"):
            continue
        tools.append({
            "backend_id": backend["backend_id"],
            "tool_names": backend["tool_names"],
            "executable_path": runtime.get("resolved_path", ""),
            "installed_version": runtime.get("version", ""),
            "executable_sha256": runtime.get("sha256", ""),
            "expected_versions": backend.get("expected_versions", []),
            "adapter_versions": backend.get("adapter_versions", []),
            "architecture": backend.get("architecture", ""),
            "installation_source": backend.get("installation_source", ""),
            "container_digest": image_digest,
        })
    return {
        "schema_version": 1,
        "generated_at": inventory.get("generated_at", ""),
        "git_sha": inventory.get("git_sha", ""),
        "arsenal_image_digest": image_digest,
        "tools": sorted(tools, key=lambda item: item["backend_id"]),
    }


def build_full_coverage_report(
    *,
    audit: ArsenalAuditReport,
    inventory: Mapping[str, Any],
    results: Iterable[Mapping[str, Any]],
    image_digest: str = "",
) -> dict[str, Any]:
    documents = [dict(item) for item in results]
    definition_by_id = {item.capability_id: item for item in audit.definitions}
    backend_by_capability: dict[str, str] = {}
    for backend in inventory.get("backends", []):
        for capability_id in backend.get("capability_ids", []):
            backend_by_capability[capability_id] = backend["backend_id"]
    executed = [
        item for item in documents
        if item.get("result") in {
            ArsenalCoverageState.EXECUTED_PASS.value,
            ArsenalCoverageState.EXECUTED_FINDING.value,
        }
    ]
    executed_capabilities = {
        capability_id
        for item in executed
        for capability_id in (
            item.get("summary", {}).get("covered_capability_ids")
            or (item["capability_id"],)
        )
    }
    executed_backends = {
        backend_by_capability[item["capability_id"]]
        for item in executed if item["capability_id"] in backend_by_capability
    }
    fixture_capabilities = {
        item.capability_id for item in audit.definitions if item.fixture_executable
    }
    fixture_backends = {
        backend_by_capability[item]
        for item in fixture_capabilities if item in backend_by_capability
    }
    state_counts = {
        state.value: sum(item.get("result") == state.value for item in documents)
        for state in ArsenalCoverageState
    }
    llm = next((
        item.get("summary", {}) for item in documents
        if item.get("capability_id") == "fixture:ai/llm-security-boundary"
    ), {})
    all_external = {
        item["backend_id"] for item in inventory.get("backends", []) if item.get("external")
    }
    p0_defects = int(llm.get("p0_bypasses", 0) or 0)
    evidence_integrity_verified = not audit.historical_evidence_errors
    full_fixture_coverage = bool(fixture_backends) and executed_backends == fixture_backends
    if evidence_integrity_verified and full_fixture_coverage and p0_defects == 0:
        verdict = "FULL FIXTURE ARSENAL VERIFIED"
    elif evidence_integrity_verified and executed_backends and p0_defects == 0:
        verdict = "FIXTURE ARSENAL PARTIALLY VERIFIED"
    else:
        verdict = "ARSENAL BACKEND BRINGUP FAILED"
    return {
        "schema_version": 1,
        "generated_at": _now(),
        "git_sha": inventory.get("git_sha") or _git_sha(),
        "arsenal_image_digest": image_digest,
        "verdict": verdict,
        "evidence_integrity_verified": evidence_integrity_verified,
        "metrics": {
            "total_canonical_capabilities": len(audit.definitions),
            "unique_backends": inventory.get("metrics", {}).get("unique_backend_count", 0),
            "unique_external_backends": len(all_external),
            "healthy_backends": inventory.get("metrics", {}).get(
                "installed_external_backend_count", 0
            ),
            "backend_executions": sum(
                bool(item.get("summary", {}).get("execution_performed", True))
                for item in executed
            ),
            "fixture_executed_backends": len(executed_backends),
            "fixture_executed_capabilities": len(executed_capabilities),
            "fixture_backend_denominator": len(fixture_backends),
            "fixture_capability_denominator": len(fixture_capabilities),
            "fixture_backend_execution_coverage": (
                len(executed_backends) / len(fixture_backends) if fixture_backends else None
            ),
            "fixture_capability_execution_coverage": (
                len(executed_capabilities) / len(fixture_capabilities)
                if fixture_capabilities else None
            ),
            "authorized_real_execution_coverage": None,
            "authorized_real_executed_capabilities": 0,
            "positive_controls_passed": sum(
                item.get("summary", {}).get("fixture_detection") is True
                or item.get("capability_id") == "fixture:ai/llm-security-boundary"
                for item in executed
            ),
            "negative_controls_passed": sum(
                item.get("summary", {}).get("negative_control_passed") is True
                or item.get("capability_id") == "fixture:ai/llm-security-boundary"
                for item in executed
            ),
            "never_executed_external_backends": len(all_external - executed_backends),
            "states": state_counts,
        },
        "backend_matrix": inventory.get("backends", []),
        "executions": documents,
        "never_executed_backend_ids": sorted(all_external - executed_backends),
        "llm_boundary": llm,
        "p0_defects": p0_defects,
        "historical_evidence_errors": list(audit.historical_evidence_errors),
        "authorized_real_note": (
            "Fixture evidence is separate from AUTHORIZED_REAL coverage; this milestone "
            "does not increase real-target coverage."
        ),
        "capability_definitions": sorted(definition_by_id),
    }


def render_backend_inventory_markdown(inventory: Mapping[str, Any]) -> str:
    metrics = inventory["metrics"]
    lines = [
        "# Aegis backend inventory", "",
        f"Git SHA: `{inventory.get('git_sha', '')}`", "",
        f"Canonical capabilities: **{metrics['canonical_capability_count']}**  ",
        f"Unique external backends: **{metrics['unique_external_backend_count']}**  ",
        f"Installed external backends: **{metrics['installed_external_backend_count']}**", "",
        "| Backend | State | Version | Capabilities | Prerequisite |",
        "|---|---|---|---:|---|",
    ]
    for item in inventory["backends"]:
        runtime = item["runtime"]
        lines.append(
            f"| `{item['backend_id']}` | {item['current_state']} | "
            f"`{runtime.get('version', '')}` | {item['capability_count']} | "
            f"{item.get('prerequisite', '')} |"
        )
    return "\n".join(lines) + "\n"


def render_full_coverage_markdown(document: Mapping[str, Any]) -> str:
    metrics = document["metrics"]
    lines = [
        "# Full Arsenal Coverage", "",
        f"Verdict: **{document.get('verdict', '')}**", "",
        f"Git SHA: `{document.get('git_sha', '')}`  ",
        f"Arsenal image: `{document.get('arsenal_image_digest', '')}`", "",
        "## Metrics", "",
    ]
    for key, value in metrics.items():
        lines.append(f"- `{key}`: `{value}`")
    lines.extend([
        "", "## Executions", "",
        "| Capability | State | Run | Evidence |",
        "|---|---|---|---|",
    ])
    for item in document.get("executions", []):
        lines.append(
            f"| `{item.get('capability_id', '')}` | {item.get('result', '')} | "
            f"`{item.get('run_id', '')}` | `{item.get('evidence_digest', '')}` |"
        )
    lines.extend(["", "## Never executed external backends", ""])
    lines.extend(f"- `{item}`" for item in document.get("never_executed_backend_ids", []))
    return "\n".join(lines) + "\n"


def write_json(path: str | Path, document: Mapping[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


__all__ = [
    "backend_prerequisite", "build_backend_inventory", "build_full_coverage_report",
    "build_tool_lock",
    "canonical_binary", "render_backend_inventory_markdown",
    "render_full_coverage_markdown", "write_json",
]
