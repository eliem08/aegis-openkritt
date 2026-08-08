"""Bubblewrap-isolated Ghidra headless analysis for authorized local binaries.

Ghidra is intentionally not executed by the generic local CLI runner because its capability
contract requires an *isolated sandbox*. This adapter enforces that requirement operationally:
both Ghidra's ``analyzeHeadless`` launcher and Bubblewrap must be READY/pinned, and Ghidra runs
inside a Bubblewrap namespace with no host network namespace and a read-only host filesystem.
Only a private per-run workspace is writable.

The adapter performs analysis only. It does not produce a vulnerability claim by itself; its
logs/output manifest are observations for later specialist reasoning and evidence stages.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import signal
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..tool_runtime import (
    ToolPin,
    ToolRuntimeManager,
    ToolRuntimeStatus,
    load_tool_pins,
    provenance,
)
from .asset_cli_executor import CliOutputArtifact
from .asset_execution_ticket import AssetExecutionTicket


class GhidraSandboxError(RuntimeError):
    """Fail-closed Ghidra sandbox setup or execution error."""


@dataclass(frozen=True)
class GhidraSandboxProcessResult:
    returncode: int
    stdout: bytes = field(default=b"", repr=False)
    stderr: bytes = field(default=b"", repr=False)
    timed_out: bool = False


@dataclass(frozen=True)
class GhidraSandboxExecution:
    returncode: int
    timed_out: bool
    provenance: dict
    stdout_sha256: str
    stderr_sha256: str
    stdout_size: int
    stderr_size: int
    outputs: tuple[CliOutputArtifact, ...]
    analysis_log_sha256: str
    analysis_log_size: int
    workspace: str
    retained_workspace: bool
    raw_stdout: bytes = field(default=b"", repr=False)
    raw_stderr: bytes = field(default=b"", repr=False)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


SandboxRunner = Callable[
    [list[str], Path, float, dict[str, str], int], GhidraSandboxProcessResult
]


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path, maximum_bytes: int) -> str:
    if not path.is_file() or path.stat().st_size > maximum_bytes:
        return ""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_ghidra_binary() -> str:
    explicit = os.environ.get("AEGIS_GHIDRA_ANALYZE_HEADLESS", "").strip()
    if explicit:
        return explicit
    home = os.environ.get("GHIDRA_HOME", "").strip()
    if home:
        candidate = Path(home).expanduser().resolve() / "support" / "analyzeHeadless"
        return str(candidate)
    return "analyzeHeadless"


def _resolve_bwrap_binary() -> str:
    return os.environ.get("AEGIS_BWRAP_PATH", "").strip() or "bwrap"


def _pin(pins: dict[str, ToolPin], name: str, binary: str) -> ToolPin | None:
    return pins.get(name) or pins.get(name.lower()) or pins.get(binary)


def _safe_environment(workspace: Path) -> dict[str, str]:
    """Minimal environment passed to Bubblewrap itself; sandbox env is rebuilt with --clearenv."""
    env: dict[str, str] = {}
    for key in ("PATH", "LANG", "LC_ALL", "JAVA_HOME"):
        value = os.environ.get(key)
        if value:
            env[key] = value
    env["HOME"] = str(workspace / "home")
    env["TMPDIR"] = str(workspace / "tmp")
    return env


def _default_runner(
    argv: list[str],
    workspace: Path,
    timeout: float,
    env: dict[str, str],
    maximum_output_bytes: int,
) -> GhidraSandboxProcessResult:
    stdout_path = workspace / "stdout.bin"
    stderr_path = workspace / "stderr.bin"
    timed_out = False
    with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
        process = subprocess.Popen(
            argv,
            cwd=workspace,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=stdout_handle,
            stderr=stderr_handle,
            shell=False,
            start_new_session=True,
        )
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            finally:
                returncode = process.wait(timeout=5)
    return GhidraSandboxProcessResult(
        returncode=returncode,
        stdout=stdout_path.read_bytes()[:maximum_output_bytes],
        stderr=stderr_path.read_bytes()[:maximum_output_bytes],
        timed_out=timed_out,
    )


def _manifest(workspace: Path, maximum_output_bytes: int) -> tuple[CliOutputArtifact, ...]:
    rows: list[CliOutputArtifact] = []
    excluded = {"stdout.bin", "stderr.bin"}
    for path in sorted(workspace.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(workspace).as_posix()
        if relative in excluded or relative.startswith(("home/", "tmp/")):
            continue
        rows.append(
            CliOutputArtifact(
                relative_path=relative,
                size_bytes=path.stat().st_size,
                sha256=_sha256_file(path, maximum_output_bytes),
            )
        )
        if len(rows) >= 500:
            break
    return tuple(rows)


def _bwrap_argv(
    *,
    bwrap_path: str,
    ghidra_path: str,
    artifact: Path,
    workspace: Path,
    analysis_seconds: int,
    max_cpu: int,
) -> list[str]:
    project_dir = workspace / "project"
    project_dir.mkdir(parents=True, exist_ok=True)
    home = workspace / "home"
    tmp = workspace / "tmp"
    home.mkdir(parents=True, exist_ok=True)
    tmp.mkdir(parents=True, exist_ok=True)
    log_path = workspace / "ghidra.log"
    path_value = os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")
    java_home = os.environ.get("JAVA_HOME", "").strip()

    argv = [
        bwrap_path,
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--ro-bind", "/", "/",
        "--bind", str(workspace), str(workspace),
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--chdir", str(workspace),
        "--setenv", "HOME", str(home),
        "--setenv", "TMPDIR", "/tmp",
        "--setenv", "PATH", path_value,
    ]
    if java_home:
        argv.extend(("--setenv", "JAVA_HOME", java_home))
    argv.extend(
        (
            "--",
            ghidra_path,
            str(project_dir),
            "AegisTemporaryProject",
            "-import", str(artifact),
            "-readOnly",
            "-analysisTimeoutPerFile", str(analysis_seconds),
            "-max-cpu", str(max_cpu),
            "-log", str(log_path),
            "-deleteProject",
        )
    )
    return argv


def execute_ghidra_sandboxed(
    *,
    artifact_path: str | Path,
    ticket: AssetExecutionTicket,
    workspace_root: str | Path | None = None,
    retain_workspace: bool = False,
    timeout: float = 600.0,
    analysis_seconds: int = 300,
    max_cpu: int = 2,
    maximum_output_bytes: int = 32 * 1024 * 1024,
    runtime_manager: ToolRuntimeManager | None = None,
    pins: dict[str, ToolPin] | None = None,
    runner: SandboxRunner | None = None,
) -> GhidraSandboxExecution:
    """Run Ghidra headless only with an artifact+sandbox execution ticket and Bubblewrap."""
    if "authorized_artifact" not in ticket.requirements or "isolated_sandbox" not in ticket.requirements:
        raise GhidraSandboxError("Ghidra ticket must require authorized_artifact and isolated_sandbox")
    if not ticket.offline_only:
        raise GhidraSandboxError("Ghidra sandbox execution requires an offline-only ticket")
    if os.name != "posix" and runner is None:
        raise GhidraSandboxError("production Bubblewrap Ghidra backend is Linux/POSIX only")

    artifact = Path(artifact_path).expanduser().resolve()
    if not artifact.is_file():
        raise GhidraSandboxError("Ghidra artifact must be an existing regular file")
    if not 1 <= int(analysis_seconds) <= 1800:
        raise GhidraSandboxError("analysis_seconds must be in [1, 1800]")
    if not 1 <= int(max_cpu) <= 64:
        raise GhidraSandboxError("max_cpu must be in [1, 64]")
    if not 1 <= float(timeout) <= 3600:
        raise GhidraSandboxError("timeout must be in [1, 3600]")

    manager = runtime_manager or ToolRuntimeManager()
    configured_pins = pins if pins is not None else load_tool_pins()
    ghidra_binary = _resolve_ghidra_binary()
    bwrap_binary = _resolve_bwrap_binary()
    ghidra = manager.inspect(
        name="Ghidra",
        binary=ghidra_binary,
        pin=_pin(configured_pins, "Ghidra", ghidra_binary),
        refresh=True,
    )
    bwrap = manager.inspect(
        name="bubblewrap",
        binary=bwrap_binary,
        pin=_pin(configured_pins, "bubblewrap", bwrap_binary),
        refresh=True,
    )
    if ghidra.status is not ToolRuntimeStatus.READY:
        raise GhidraSandboxError(f"Ghidra runtime is {ghidra.status.value}: {ghidra.reason}")
    if bwrap.status is not ToolRuntimeStatus.READY:
        raise GhidraSandboxError(f"Bubblewrap runtime is {bwrap.status.value}: {bwrap.reason}")

    root = Path(workspace_root).expanduser().resolve() if workspace_root else None
    if root is not None:
        root.mkdir(parents=True, exist_ok=True)
    workspace = Path(tempfile.mkdtemp(prefix="aegis-ghidra-", dir=str(root) if root else None))
    argv = _bwrap_argv(
        bwrap_path=bwrap.resolved_path,
        ghidra_path=ghidra.resolved_path,
        artifact=artifact,
        workspace=workspace,
        analysis_seconds=int(analysis_seconds),
        max_cpu=int(max_cpu),
    )
    process_runner = runner or _default_runner
    try:
        process = process_runner(
            argv,
            workspace,
            float(timeout),
            _safe_environment(workspace),
            int(maximum_output_bytes),
        )
        stdout = bytes(process.stdout[:maximum_output_bytes])
        stderr = bytes(process.stderr[:maximum_output_bytes])
        log = workspace / "ghidra.log"
        log_size = log.stat().st_size if log.is_file() else 0
        log_digest = _sha256_file(log, maximum_output_bytes)
        outputs = _manifest(workspace, maximum_output_bytes)
        prov = provenance(ghidra, argv[argv.index("--") + 1 :])
        prov.update(
            {
                "execution_mode": "bubblewrap_ghidra",
                "sandbox": {
                    "tool": "bubblewrap",
                    "version": bwrap.version,
                    "binary_sha256": bwrap.sha256,
                    "unshare_all": True,
                    "network_shared": False,
                    "host_root": "read_only",
                    "writable_workspace_only": True,
                },
                "execution_ticket": ticket.ticket_id,
                "scope_digest": ticket.scope_digest,
                "shell": False,
            }
        )
        result = GhidraSandboxExecution(
            returncode=int(process.returncode),
            timed_out=bool(process.timed_out),
            provenance=prov,
            stdout_sha256=_sha256_bytes(stdout),
            stderr_sha256=_sha256_bytes(stderr),
            stdout_size=len(stdout),
            stderr_size=len(stderr),
            outputs=outputs,
            analysis_log_sha256=log_digest,
            analysis_log_size=log_size,
            workspace=str(workspace) if retain_workspace else "",
            retained_workspace=retain_workspace,
            raw_stdout=stdout,
            raw_stderr=stderr,
        )
    except Exception:
        if not retain_workspace:
            shutil.rmtree(workspace, ignore_errors=True)
        raise

    if not retain_workspace:
        shutil.rmtree(workspace, ignore_errors=True)
    return result


def cleanup_ghidra_execution(execution: GhidraSandboxExecution) -> None:
    if not execution.retained_workspace or not execution.workspace:
        return
    path = Path(execution.workspace).resolve()
    if path.name.startswith("aegis-ghidra-"):
        shutil.rmtree(path, ignore_errors=True)
