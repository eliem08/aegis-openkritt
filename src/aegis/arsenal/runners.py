"""Canonical execution-runner profiles for external arsenal runtimes.

Profiles describe infrastructure only.  They never authorize an exercise; target-facing
execution still enters through MissionPlan -> PolicyEngine -> signed ExecutionGrant.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Mapping


@dataclass(frozen=True, slots=True)
class RunnerProfile:
    runner_profile: str
    os: str
    privileged: bool
    docker: bool
    network_mode: str
    qemu: bool = False
    binfmt: bool = False
    kvm: str = "not-required"
    required_commands: tuple[str, ...] = ()
    required_environment: tuple[str, ...] = ()
    description: str = ""

    def document(self) -> dict[str, Any]:
        return asdict(self)


RUNNER_PROFILES: tuple[RunnerProfile, ...] = (
    RunnerProfile("arsenal-core", "any", False, False, "none", description=(
        "Aegis internal fixtures, inventory, evidence verification, and policy tests"
    )),
    RunnerProfile("arsenal-linux", "linux", False, True, "none", required_commands=(
        "docker",
    ), description="Pinned Linux CLI/static-analysis image"),
    RunnerProfile("arsenal-network-lab", "linux", False, True, "isolated", required_commands=(
        "docker",
    ), description="Isolated Docker network with deterministic local services"),
    RunnerProfile("arsenal-android", "linux", False, True, "isolated", required_commands=(
        "adb", "emulator",
    ), required_environment=("ANDROID_HOME",), description=(
        "Operator-owned Android emulator and synthetic APK"
    )),
    RunnerProfile("arsenal-firmware", "linux", True, True, "isolated", qemu=True,
                  binfmt=True, kvm="optional", required_commands=(
                      "docker", "qemu-system-x86_64", "binwalk",
                  ), description="Privileged QEMU/binfmt synthetic firmware lab"),
    RunnerProfile("arsenal-binary", "linux", False, True, "none", required_commands=(
        "gcc", "file",
    ), description="Deterministic ELF/PE analysis fixtures"),
    RunnerProfile("arsenal-smart-contract", "linux", False, True, "none",
                  required_commands=("solc",), description=(
                      "Pinned Solidity compiler, static analyzers, and invariant tools"
                  )),
    RunnerProfile("arsenal-kubernetes", "linux", False, True, "isolated",
                  required_commands=("docker", "kubectl", "kind"), description=(
                      "Disposable local Kubernetes cluster"
                  )),
    RunnerProfile("arsenal-cloud-lab", "linux", False, True, "allowlisted",
                  required_environment=("AEGIS_CLOUD_LAB_AUTHORIZATION",), description=(
                      "Operator-owned disposable cloud sandbox; never a bounty target"
                  )),
    RunnerProfile("arsenal-macos-ios", "macos", False, False, "none",
                  required_commands=("xcrun", "xcodebuild", "otool"), description=(
                      "macOS runner with iOS Simulator and synthetic application"
                  )),
    RunnerProfile("arsenal-llm", "any", False, False, "none", description=(
        "Deterministic 16-case local AI/LLM boundary lab"
    )),
    RunnerProfile("arsenal-postgres", "any", False, False, "loopback",
                  required_environment=("AEGIS_ARSENAL_COVERAGE_DB_URL",), description=(
                      "Authoritative PostgreSQL coverage projection"
                  )),
)

_PROFILE_BY_BINARY = {
    "adb": "arsenal-android", "apktool": "arsenal-android",
    "frida": "arsenal-android", "jadx": "arsenal-android",
    "mobsf": "arsenal-android", "objection": "arsenal-android",
    "class-dump": "arsenal-macos-ios", "otool": "arsenal-macos-ios",
    "firmadyne": "arsenal-firmware", "firmae": "arsenal-firmware",
    "binwalk": "arsenal-firmware",
    "analyzeheadless": "arsenal-binary", "angr": "arsenal-binary",
    "capa": "arsenal-binary", "floss": "arsenal-binary", "pefile": "arsenal-binary",
    "rizin": "arsenal-binary", "yara": "arsenal-binary",
    "echidna": "arsenal-smart-contract", "forge": "arsenal-smart-contract",
    "myth": "arsenal-smart-contract", "slither": "arsenal-smart-contract",
    "kubescape": "arsenal-kubernetes",
    "azurehound": "arsenal-cloud-lab", "cloudsplaining": "arsenal-cloud-lab",
    "prowler": "arsenal-cloud-lab", "roadrecon": "arsenal-cloud-lab",
    "scout": "arsenal-cloud-lab",
    "dnsx": "arsenal-network-lab", "gau": "arsenal-network-lab",
    "grpcurl": "arsenal-network-lab", "http-probe": "arsenal-network-lab",
    "httpx": "arsenal-network-lab", "katana": "arsenal-network-lab",
    "mitmproxy": "arsenal-network-lab", "naabu": "arsenal-network-lab",
    "nmap": "arsenal-network-lab", "nuclei": "arsenal-network-lab",
    "restler": "arsenal-network-lab", "rustscan": "arsenal-network-lab",
    "schemathesis": "arsenal-network-lab", "ssh-audit": "arsenal-network-lab",
    "subfinder": "arsenal-network-lab", "testssl.sh": "arsenal-network-lab",
    "websocat": "arsenal-network-lab",
}

_RUNTIME_ALIASES = {
    "analyzeheadless": "ghidra/headless", "apktool": "apktool/linux-cli",
    "asar": "electron-asar/node-cli", "class-dump": "class-dump/macos-cli",
    "firmae": "firmae/qemu-lab", "firmadyne": "firmadyne/qemu-lab",
    "forge": "foundry/forge", "frida": "frida/device-cli", "mobsf": "mobsf/container",
    "myth": "mythril/linux-cli", "otool": "otool/macos-cli",
    "retire": "retire-js/node-cli", "scout": "scoutsuite/cloud-cli",
    "testssl.sh": "testssl-sh/linux-cli",
}


def runner_profile_for_binary(binary: str) -> str:
    return _PROFILE_BY_BINARY.get(str(binary).strip().casefold(), "arsenal-linux")


def backend_runtime_id(binary: str, *, runner_profile: str | None = None) -> str:
    normalized = str(binary).strip().casefold()
    if normalized in _RUNTIME_ALIASES:
        return _RUNTIME_ALIASES[normalized]
    profile = runner_profile or runner_profile_for_binary(normalized)
    suffix = {
        "arsenal-macos-ios": "macos-cli",
        "arsenal-android": "android-lab",
        "arsenal-firmware": "firmware-lab",
        "arsenal-network-lab": "network-lab",
        "arsenal-cloud-lab": "cloud-lab",
        "arsenal-kubernetes": "kubernetes-lab",
        "arsenal-smart-contract": "contract-cli",
    }.get(profile, "linux-cli")
    return f"{normalized}/{suffix}"


def _command_ready(command: str) -> bool:
    return shutil.which(command) is not None


def _docker_image_ready() -> bool:
    if not _command_ready("docker"):
        return False
    image = os.environ.get("AEGIS_ARSENAL_IMAGE", "aegis-arsenal:bringup")
    try:
        return subprocess.run(
            ["docker", "image", "inspect", image], capture_output=True,
            check=False, timeout=15,
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def runner_readiness(
    profiles: Iterable[RunnerProfile] = RUNNER_PROFILES,
    *, backend_runtimes: Mapping[str, Iterable[str]] | None = None,
    executable_runtimes: Mapping[str, Iterable[str]] | None = None,
) -> dict[str, Any]:
    host = platform.system().casefold()
    rows = []
    mapping = backend_runtimes or {}
    executable_mapping = executable_runtimes or {}
    for profile in profiles:
        missing: list[str] = []
        os_ready = profile.os == "any" or profile.os == host
        if not os_ready and not (
            host == "windows" and profile.os == "linux" and _docker_image_ready()
        ):
            missing.append(f"requires {profile.os} runner")
        for command in profile.required_commands:
            if not _command_ready(command):
                if not (profile.os == "linux" and _docker_image_ready()):
                    missing.append(f"command:{command}")
        for name in profile.required_environment:
            if not os.environ.get(name, "").strip():
                missing.append(f"environment:{name}")
        if profile.privileged and os.environ.get(
            "AEGIS_PRIVILEGED_FIXTURE_RUNNER", ""
        ).strip().casefold() not in {"1", "true", "yes"}:
            missing.append("privileged-runner-approval")
        supported = sorted(set(mapping.get(profile.runner_profile, ())))
        executable = sorted(set(executable_mapping.get(profile.runner_profile, ())))
        not_executed = sorted(set(supported) - set(executable))
        if supported and not_executed:
            missing.append(f"unverified-runtimes:{len(not_executed)}")
        rows.append({
            **profile.document(),
            "available": not missing,
            "status": "READY" if not missing else "WAITING_FOR_PREREQUISITE",
            "missing_prerequisites": missing,
            "backend_runtimes_supported": supported,
            "backend_runtimes_currently_executable": executable,
            "backend_runtimes_not_yet_executed": not_executed,
            "runtime_execution_coverage": (
                len(executable) / len(supported) if supported else None
            ),
        })
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "host": {"os": host, "architecture": platform.machine()},
        "profiles": rows,
    }


def render_runner_markdown(document: Mapping[str, Any]) -> str:
    lines = [
        "# Arsenal runner matrix", "",
        "| Runner | Platform | State | Missing prerequisites | Runtime count |",
        "|---|---|---|---|---:|",
    ]
    for row in document.get("profiles", []):
        lines.append(
            f"| `{row['runner_profile']}` | {row['os']} | **{row['status']}** | "
            f"{', '.join(row['missing_prerequisites']) or '-'} | "
            f"{len(row['backend_runtimes_supported'])} |"
        )
    return "\n".join(lines) + "\n"


def write_runner_profiles(path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps({
        "schema_version": 1,
        "profiles": [item.document() for item in RUNNER_PROFILES],
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")


__all__ = [
    "RUNNER_PROFILES", "RunnerProfile", "backend_runtime_id", "render_runner_markdown",
    "runner_profile_for_binary", "runner_readiness", "write_runner_profiles",
]
