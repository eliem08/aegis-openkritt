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
from aegis.production.operator_manifest import document_digest

from .migrations import RUNTIME_MIGRATIONS
from .models import (
    ArsenalAuditReport,
    ArsenalCoverageState,
    CapabilityDefinition,
    ExecutionProofKind,
)
from .runners import backend_runtime_id, runner_profile_for_binary
from .tool_exercise import fixture_version_for_capability

_INTERNAL_PREFIXES = ("aegis-", "stdlib-")
_BINARY_ALIASES = {
    "electron-asar": "asar",
    "foundry": "forge",
    "ghidra": "analyzeHeadless",
    "http-probe": "httpx",
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
    "gau": "operator-owned domain fixture with explicitly approved passive-provider endpoints; readiness: test -n \"$AEGIS_PASSIVE_PROVIDER_AUTHORIZATION\"",
    "subfinder": "operator-owned domain fixture with explicitly approved passive-provider endpoints; readiness: test -n \"$AEGIS_PASSIVE_PROVIDER_AUTHORIZATION\"",
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
            runner_profile = runner_profile_for_binary(binary)
            rows.append({
                "backend_id": f"{'external' if external else 'internal'}:{binary}",
                "backend_runtime_id": (
                    backend_runtime_id(binary, runner_profile=runner_profile)
                    if external else f"aegis/{binary or backends[0].backend_id}"
                ),
                "runner_profile": runner_profile if external else "arsenal-core",
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
    logical_backend_claims = sum(
        len(item.tool_backends) for item in report.definitions
    )
    external_runtime_ids = {
        item["backend_runtime_id"] for item in external_rows
    }
    return {
        "schema_version": 1,
        "generated_at": _now(),
        "git_sha": _git_sha(),
        "metrics": {
            "canonical_capability_count": len(report.definitions),
            "logical_backend_count": logical_backend_claims,
            "unique_backend_count": len(rows),
            "unique_external_backend_count": len(external_rows),
            "unique_external_executable_runtime_count": len(external_runtime_ids),
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
            "backend_runtime_id": backend.get("backend_runtime_id", backend["backend_id"]),
            "runner_profile": backend.get("runner_profile", ""),
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


def build_runtime_lock(inventory: Mapping[str, Any], *, image_digest: str = "") -> dict[str, Any]:
    """Create the exhaustive runtime-installation manifest from canonical inventory.

    Unknown installation metadata remains explicit.  The lock is not proof of execution; its
    records are joined with coverage evidence by ``backend_runtime_id``.
    """
    rows = []
    for backend in inventory.get("backends", []):
        if not backend.get("external"):
            continue
        runtime = dict(backend.get("runtime") or {})
        binary = str(backend.get("binary") or "")
        profile = str(backend.get("runner_profile") or runner_profile_for_binary(binary))
        expected = list(backend.get("expected_versions", ()))
        installed = str(runtime.get("version") or "")
        rows.append({
            "backend_runtime_id": backend.get("backend_runtime_id") or backend_runtime_id(
                binary, runner_profile=profile,
            ),
            "name": ",".join(backend.get("tool_names", ())) or binary,
            "version": installed or (expected[0] if expected else "UNRESOLVED"),
            "platforms": [profile],
            "installation_method": (
                "pinned-container-image" if runtime.get("resolved_path") else "UNRESOLVED"
            ),
            "source": backend.get("installation_source", "UNRESOLVED"),
            "sha256": str(runtime.get("sha256") or ""),
            "binary": binary,
            "health_probe": [binary, "--version"] if binary else [],
            "runner_profile": profile,
            "resource_limits": {
                "wall_clock_seconds": 1200,
                "cpu": 4,
                "ram_mb": 6144,
                "output_bytes": 8388608,
                "process_count": 512,
                "concurrency": 1,
            },
            "network_policy": (
                "isolated-fixture-network" if profile in {
                    "arsenal-network-lab", "arsenal-android", "arsenal-firmware",
                    "arsenal-kubernetes",
                } else "none"
            ),
            "fixture_provider": list(backend.get("fixture_providers", ())),
            "capability_ids": list(backend.get("capability_ids", ())),
            "container_digest": image_digest,
            "status": str(runtime.get("status") or "unavailable"),
        })
    return {
        "schema_version": 1,
        "generated_at": inventory.get("generated_at", ""),
        "git_sha": inventory.get("git_sha", ""),
        "runtimes": sorted(rows, key=lambda item: item["backend_runtime_id"]),
    }


_INTERNAL_AEGIS_BACKEND_IDS = {
    "internal:aegis-agent-permission-audit",
    "internal:aegis-artifact-diff",
    "internal:aegis-asset-classifier",
    "internal:aegis-firmware-arch",
    "internal:aegis-memory-poisoning",
    "internal:aegis-model-provenance",
    "internal:aegis-rag-boundary",
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

    external_backends_all = [
        item for item in inventory.get("backends", []) if item.get("external")
    ]
    internal_backends_all = [
        item for item in inventory.get("backends", [])
        if not item.get("external")
        and (item.get("backend_id") in _INTERNAL_AEGIS_BACKEND_IDS or bool(item.get("fixture_executable_capabilities")))
    ]

    external_backend_by_capability: dict[str, str] = {}
    for backend in external_backends_all:
        for capability_id in backend.get("capability_ids", []):
            external_backend_by_capability[capability_id] = backend["backend_id"]

    internal_backend_by_capability: dict[str, str] = {}
    for backend in internal_backends_all:
        for capability_id in backend.get("capability_ids", []):
            internal_backend_by_capability[capability_id] = backend["backend_id"]

    backend_by_capability = {**internal_backend_by_capability, **external_backend_by_capability}

    migrated_ids = {m.old_runtime_id for m in RUNTIME_MIGRATIONS}
    migrated_binaries = {
        m.old_runtime_id.split("/")[0] for m in RUNTIME_MIGRATIONS
    } | {"class-dump", "firmadyne"}

    migrated_backends = [
        item for item in external_backends_all
        if item.get("binary") in migrated_binaries or item.get("backend_runtime_id") in migrated_ids
    ]
    active_external_backends = [
        item for item in external_backends_all
        if item not in migrated_backends
    ]
    active_external_backend_ids = {item["backend_id"] for item in active_external_backends}

    active_internal_backends = list(internal_backends_all)
    active_internal_backend_ids = {item["backend_id"] for item in active_internal_backends}

    executed = [
        item for item in documents
        if item.get("result") in {
            ArsenalCoverageState.EXECUTED_PASS.value,
            ArsenalCoverageState.EXECUTED_FINDING.value,
        }
        and item.get("summary", {}).get("execution_proof_kind") in {
            ExecutionProofKind.REAL_BACKEND.value,
            ExecutionProofKind.REAL_BACKEND_SHARED_CAPABILITIES.value,
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

    executed_external_backends = {
        external_backend_by_capability[item["capability_id"]]
        for item in executed if item["capability_id"] in external_backend_by_capability
    }
    executed_internal_backends = {
        internal_backend_by_capability[item["capability_id"]]
        for item in executed if item["capability_id"] in internal_backend_by_capability
    }

    executed_active_external = executed_external_backends & active_external_backend_ids
    never_executed_active_external = sorted(active_external_backend_ids - executed_external_backends)

    executed_active_internal = executed_internal_backends & active_internal_backend_ids
    never_executed_active_internal = sorted(active_internal_backend_ids - executed_internal_backends)

    fixture_capabilities = {
        item.capability_id for item in audit.definitions if item.fixture_executable
    }
    state_counts = {
        state.value: sum(item.get("result") == state.value for item in documents)
        for state in ArsenalCoverageState
    }
    llm = next((
        item.get("summary", {}) for item in documents
        if item.get("capability_id") == "fixture:ai/llm-security-boundary"
    ), {})
    p0_defects = int(llm.get("p0_bypasses", 0) or 0)
    evidence_integrity_verified = not audit.historical_evidence_errors

    registered_external_count = len(external_backends_all)
    migrated_backend_count = len(migrated_backends)
    active_external_count = len(active_external_backends)
    executed_external_count = len(executed_active_external)
    never_executed_external_count = len(never_executed_active_external)

    registered_internal_count = len(internal_backends_all)
    active_internal_count = len(active_internal_backends)
    executed_internal_count = len(executed_active_internal)
    never_executed_internal_count = len(never_executed_active_internal)

    external_coverage = (
        executed_external_count / active_external_count
        if active_external_count else 0.0
    )
    internal_coverage = (
        executed_internal_count / active_internal_count
        if active_internal_count else 0.0
    )
    overall_active_count = active_external_count + active_internal_count
    overall_executed_count = executed_external_count + executed_internal_count
    overall_coverage = (
        overall_executed_count / overall_active_count
        if overall_active_count else 0.0
    )

    verified_shared_backend_executions = sum(
        1 for item in executed
        if len(item.get("summary", {}).get("covered_capability_ids") or ()) > 1
    )
    verified_real_capabilities = len(executed_capabilities)
    migrated_capabilities = len(migrated_ids)

    positive_controls = sum(
        item.get("summary", {}).get("fixture_detection") is True
        or item.get("capability_id") == "fixture:ai/llm-security-boundary"
        for item in executed
    )
    negative_controls = sum(
        item.get("summary", {}).get("negative_control_passed") is True
        or item.get("capability_id") == "fixture:ai/llm-security-boundary"
        for item in executed
    )

    unavailable_count = sum(
        1 for item in active_external_backends
        if item.get("backend_id") in never_executed_active_external
        and item.get("current_state") == ArsenalCoverageState.UNAVAILABLE.value
    )
    backend_unhealthy_count = sum(
        1 for item in active_external_backends
        if item.get("backend_id") in never_executed_active_external
        and item.get("current_state") == ArsenalCoverageState.BACKEND_UNHEALTHY.value
    )
    denied_count = sum(
        1 for item in active_external_backends
        if item.get("backend_id") in never_executed_active_external
        and item.get("current_state") in {
            ArsenalCoverageState.DENIED_BY_POLICY.value,
            ArsenalCoverageState.DENIED_POLICY_AMBIGUOUS.value,
        }
    )
    waiting_prerequisite_count = max(
        0, never_executed_external_count - unavailable_count - backend_unhealthy_count - denied_count
    )

    populations = {
        "external": {
            "registered": registered_external_count,
            "active": active_external_count,
            "executed": executed_external_count,
            "waiting": waiting_prerequisite_count,
            "unavailable": unavailable_count,
            "unhealthy": backend_unhealthy_count,
            "denied": 0,
            "migrated": migrated_backend_count,
            "retired": 0,
            "never_executed": never_executed_external_count,
            "execution_coverage": external_coverage,
        },
        "internal_aegis": {
            "registered": registered_internal_count,
            "active": active_internal_count,
            "executed": executed_internal_count,
            "waiting": never_executed_internal_count,
            "unavailable": 0,
            "unhealthy": 0,
            "never_executed": never_executed_internal_count,
            "execution_coverage": internal_coverage,
        },
        "overall": {
            "active": overall_active_count,
            "executed": overall_executed_count,
            "never_executed": never_executed_external_count + never_executed_internal_count,
            "execution_coverage": overall_coverage,
        },
    }

    source_sha = inventory.get("git_sha") or _git_sha()
    report_time = _now()
    inv_digest = document_digest(inventory)
    runtime_lock = build_runtime_lock(inventory, image_digest=image_digest)
    lock_digest = document_digest(runtime_lock)
    fixture_digests = sorted((item.capability_id, fixture_version_for_capability(item.capability_id)) for item in audit.definitions)
    fixture_version_digest = document_digest(fixture_digests)
    evidence_items = sorted((item.run_id, item.evidence_digest) for item in audit.history if not item.historical_evidence_invalid)
    evidence_root_digest = document_digest(evidence_items)

    full_fixture_coverage = bool(active_external_backends) and len(never_executed_active_external) == 0
    active_unexecuted = set(never_executed_active_external)
    active_unexecuted_waiting = {
        item["backend_id"] for item in active_external_backends
        if item["backend_id"] in active_unexecuted
        and (
            bool(item.get("prerequisite"))
            or item.get("binary") in _PREREQUISITES
            or item.get("current_state") == ArsenalCoverageState.WAITING_FOR_PREREQUISITE.value
        )
    }
    all_unexecuted_are_waiting = bool(active_unexecuted) and active_unexecuted == active_unexecuted_waiting

    # Deterministic ordered verdict hierarchy
    if not evidence_integrity_verified or p0_defects > 0:
        verdict = "ARSENAL_CLOSURE_FAILED"
    elif full_fixture_coverage and waiting_prerequisite_count == 0 and unavailable_count == 0 and backend_unhealthy_count == 0:
        verdict = "FULL_FIXTURE_ARSENAL_VERIFIED"
    elif executed_external_count > 0 and all_unexecuted_are_waiting:
        verdict = "ACTIVE_LOCAL_SOFTWARE_SUBSET_VERIFIED_EXTERNAL_PREREQUISITES_REMAIN"
    elif executed_external_count > 0:
        verdict = "FIXTURE_ARSENAL_PARTIALLY_VERIFIED"
    else:
        verdict = "ARSENAL_CLOSURE_FAILED"

    # Historical cross-runner evidence mapping
    evidence_by_backend: dict[str, list[dict[str, Any]]] = {}
    for h in audit.history:
        if h.historical_evidence_invalid or h.state not in (
            ArsenalCoverageState.EXECUTED_PASS, ArsenalCoverageState.EXECUTED_FINDING
        ):
            continue
        bid = backend_by_capability.get(h.capability_id)
        if bid:
            plat = "Darwin" if "Darwin" in getattr(h, "binary_path", "") or h.backend == "otool" else "Linux"
            evidence_by_backend.setdefault(bid, []).append({
                "runner": "github-macos" if plat == "Darwin" else "arsenal-linux",
                "platform": plat,
                "state": h.state.value,
                "evidence_digest": h.evidence_digest,
                "source_sha": h.run_id,
                "backend_name": h.backend,
                "binary_path": getattr(h, "binary_path", ""),
            })

    execution_by_cap = {e.get("capability_id"): e for e in executed}
    backend_matrix_rows = []
    for backend in inventory.get("backends", []):
        row = dict(backend)
        binary = row.get("binary", "")
        bid = row.get("backend_id", "")
        is_migrated = binary in migrated_binaries or row.get("backend_runtime_id") in migrated_ids
        row["active_status"] = "migrated" if is_migrated else "active"
        matched_exec = next((execution_by_cap[c] for c in row.get("capability_ids", []) if c in execution_by_cap), None)

        if matched_exec:
            summary = matched_exec.get("summary", {})
            runtime_info = summary.get("positive", {}).get("runtime", {})
            row["global_execution_state"] = matched_exec.get("result", ArsenalCoverageState.EXECUTED_PASS.value)
            row["execution_proof_kind"] = summary.get("execution_proof_kind", ExecutionProofKind.REAL_BACKEND.value)
            row["launcher_executable"] = summary.get("launcher_executable", "")
            row["backend_entrypoint"] = summary.get("backend_entrypoint", "")
            row["backend_version"] = str(runtime_info.get("version", ""))
            row["native_backend_binary"] = str(runtime_info.get("resolved_path", ""))
            row["execution_run_id"] = matched_exec.get("run_id", "")
            row["evidence_digest"] = matched_exec.get("evidence_digest", "")
            row["positive_control"] = "PASS" if summary.get("fixture_detection") else "FAIL"
            row["negative_control"] = "PASS" if summary.get("negative_control_passed") else "FAIL"
        elif is_migrated:
            row["global_execution_state"] = "MIGRATED"
            row["execution_proof_kind"] = ExecutionProofKind.MIGRATED_EQUIVALENT.value
            row["launcher_executable"] = ""
            row["backend_entrypoint"] = ""
            row["backend_version"] = "MIGRATED"
            row["native_backend_binary"] = ""
            row["execution_run_id"] = ""
            row["evidence_digest"] = ""
            row["positive_control"] = "MIGRATED"
            row["negative_control"] = "MIGRATED"
        else:
            row["global_execution_state"] = ArsenalCoverageState.WAITING_FOR_PREREQUISITE.value
            row["execution_proof_kind"] = ExecutionProofKind.PREREQUISITE_ONLY.value
            row["launcher_executable"] = ""
            row["backend_entrypoint"] = ""
            row["backend_version"] = ""
            row["native_backend_binary"] = ""
            row["execution_run_id"] = ""
            row["evidence_digest"] = ""
            row["positive_control"] = "NOT_EXECUTED"
            row["negative_control"] = "NOT_EXECUTED"

        current_readiness = backend.get("current_state", ArsenalCoverageState.WAITING_FOR_PREREQUISITE.value)
        row["current_runner_readiness"] = current_readiness
        row["current_runner"] = {
            "runner": "windows-local" if platform.system() == "Windows" else "linux-runner",
            "platform": platform.system(),
            "readiness": current_readiness,
        }
        row["execution_evidence_by_runner"] = evidence_by_backend.get(bid, [])
        backend_matrix_rows.append(row)

    return {
        "schema_version": 2,
        "source_git_sha": source_sha,
        "git_sha": source_sha,
        "report_generated_at": report_time,
        "generated_at": report_time,
        "inventory_digest": inv_digest,
        "backend_lock_digest": lock_digest,
        "fixture_version_digest": fixture_version_digest,
        "evidence_root_digest": evidence_root_digest,
        "arsenal_image_digest": image_digest,
        "verdict": verdict,
        "evidence_integrity_verified": evidence_integrity_verified,
        "metrics": {
            "registered_backends": registered_external_count,
            "active_backends": active_external_count,
            "migrated_backends": migrated_backend_count,
            "verified_real_backend_executions": executed_external_count,
            "verified_shared_backend_executions": verified_shared_backend_executions,
            "verified_real_capabilities": verified_real_capabilities,
            "migrated_capabilities": migrated_capabilities,
            "never_executed_active_backends": never_executed_external_count,
            "positive_controls": positive_controls,
            "negative_controls": negative_controls,
            "waiting_prerequisite_count": waiting_prerequisite_count,
            "unavailable_count": unavailable_count,
            "backend_unhealthy_count": backend_unhealthy_count,
            "total_canonical_capabilities": len(audit.definitions),
            "unique_backends": inventory.get("metrics", {}).get("unique_backend_count", 0),
            "unique_external_backends": registered_external_count,
            "healthy_backends": inventory.get("metrics", {}).get(
                "installed_external_backend_count", 0
            ),
            "backend_executions": executed_external_count,
            "fixture_executed_backends": executed_external_count,
            "fixture_executed_capabilities": verified_real_capabilities,
            "fixture_backend_denominator": active_external_count,
            "fixture_capability_denominator": len(fixture_capabilities),
            "fixture_backend_execution_coverage": external_coverage,
            "fixture_capability_execution_coverage": (
                verified_real_capabilities / len(fixture_capabilities)
                if fixture_capabilities else None
            ),
            "external_backend_execution_coverage": external_coverage,
            "internal_backend_execution_coverage": internal_coverage,
            "overall_active_backend_execution_coverage": overall_coverage,
            "populations": populations,
            "authorized_real_execution_coverage": None,
            "authorized_real_executed_capabilities": 0,
            "positive_controls_passed": positive_controls,
            "negative_controls_passed": negative_controls,
            "never_executed_external_backends": never_executed_external_count,
            "states": state_counts,
        },
        "runtime_migrations": [m.document() for m in RUNTIME_MIGRATIONS],
        "backend_matrix": backend_matrix_rows,
        "executions": documents,
        "never_executed_backend_ids": never_executed_active_external,
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
        f"Logical backend claims: **{metrics['logical_backend_count']}**  ",
        f"Unique external backends: **{metrics['unique_external_backend_count']}**  ",
        "Unique external executable runtimes: "
        f"**{metrics['unique_external_executable_runtime_count']}**  ",
        f"Installed external backends: **{metrics['installed_external_backend_count']}**", "",
        "| Backend runtime | State | Runner | Version | Capabilities | Prerequisite |",
        "|---|---|---|---|---:|---|",
    ]
    for item in inventory["backends"]:
        runtime = item["runtime"]
        lines.append(
            f"| `{item['backend_runtime_id']}` | {item['current_state']} | "
            f"`{item['runner_profile']}` | `{runtime.get('version', '')}` | "
            f"{item['capability_count']} | "
            f"{item.get('prerequisite', '')} |"
        )
    return "\n".join(lines) + "\n"


def render_full_coverage_markdown(document: Mapping[str, Any]) -> str:
    metrics = document["metrics"]
    lines = [
        "# Full Arsenal Coverage", "",
        f"Verdict: **{document.get('verdict', '')}**", "",
        "## Exact-Head Provenance", "",
        f"- Source Git SHA: `{document.get('source_git_sha', document.get('git_sha', ''))}`",
        f"- Generated At: `{document.get('report_generated_at', document.get('generated_at', ''))}`",
        f"- Inventory Digest: `{document.get('inventory_digest', '')}`",
        f"- Backend Lock Digest: `{document.get('backend_lock_digest', '')}`",
        f"- Fixture Version Digest: `{document.get('fixture_version_digest', '')}`",
        f"- Evidence Root Digest: `{document.get('evidence_root_digest', '')}`",
        f"- Arsenal Image: `{document.get('arsenal_image_digest', '')}`", "",
    ]
    lines.extend([
        "## Typed Populations", "",
        "| Population | Registered | Active | Executed | Never Executed | Coverage |",
        "|---|---:|---:|---:|---:|---:|",
        f"| External Tools | {metrics['populations']['external']['registered']} | {metrics['populations']['external']['active']} | {metrics['populations']['external']['executed']} | {metrics['populations']['external']['never_executed']} | {metrics['populations']['external']['execution_coverage']:.2%} |",
        f"| Internal Aegis | {metrics['populations']['internal_aegis']['registered']} | {metrics['populations']['internal_aegis']['active']} | {metrics['populations']['internal_aegis']['executed']} | {metrics['populations']['internal_aegis']['never_executed']} | {metrics['populations']['internal_aegis']['execution_coverage']:.2%} |",
        f"| Overall Active | - | {metrics['populations']['overall']['active']} | {metrics['populations']['overall']['executed']} | {metrics['populations']['overall']['never_executed']} | {metrics['populations']['overall']['execution_coverage']:.2%} |",
        "",
        "## Metrics", "",
    ])
    for key, value in metrics.items():
        if key == "populations":
            continue
        lines.append(f"- `{key}`: `{value}`")

    lines.extend([
        "", "## Runtime Migrations", "",
        "| Old Runtime | Replacement | Reason | Semantics | Old Binary Executed | In Execution Denominator |",
        "|---|---|---|---|---|---|",
    ])
    for mig in document.get("runtime_migrations", []):
        lines.append(
            f"| `{mig.get('old_runtime_id')}` | `{mig.get('replacement_runtime_id')}` | "
            f"{mig.get('reason')} | {mig.get('old_semantics')} -> {mig.get('replacement_semantics')} | "
            f"No | No (Migrated) |"
        )

    lines.extend([
        "", "## Backend Execution Matrix", "",
        "| Backend Runtime | Kind | Active/Migrated | Runner | Proof Kind | Positive | Negative | State |",
        "|---|---|---|---|---|---|---|---|",
    ])
    for b in document.get("backend_matrix", []):
        lines.append(
            f"| `{b.get('backend_runtime_id')}` | {b.get('active_status', 'active')} | "
            f"{'EXTERNAL_TOOL' if b.get('external') else 'INTERNAL_AEGIS'} | "
            f"`{b.get('runner_profile')}` | `{b.get('execution_proof_kind', '')}` | "
            f"{b.get('positive_control', '')} | {b.get('negative_control', '')} | "
            f"{b.get('current_state', '')} |"
        )

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
    lines.extend(["", "## Never Executed Active Backends", ""])
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
    "build_runtime_lock", "build_tool_lock",
    "canonical_binary", "render_backend_inventory_markdown",
    "render_full_coverage_markdown", "write_json",
]
