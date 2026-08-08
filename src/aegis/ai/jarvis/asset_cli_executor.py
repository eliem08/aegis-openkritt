"""Guarded local CLI execution for offline heterogeneous-asset methods.

This is the execution counterpart to ``asset_runtime.overlay_runtime``. It is deliberately
narrow: only methods declared local-only, network-free and non-state-changing may enter this
executor. The exact binary must be READY in ``ToolRuntimeManager`` and optional worker pins are
rechecked immediately before execution.

Security properties:
- argv arrays only; never ``shell=True``;
- target inputs must be existing local files/directories;
- all generated output is confined to a private per-run workspace;
- common credentials/proxy settings are removed from the child environment;
- bounded wall time and captured output; POSIX workers additionally receive CPU/file-size limits;
- exact executable path/version/SHA-256 and argv are recorded as provenance;
- output is operational evidence only, never a confirmed vulnerability by itself.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import signal
import string
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
from .asset_deep_capabilities import PlannedMethod
from .asset_runtime import method_binary

_ALLOWED_PLACEHOLDERS = frozenset(
    {"artifact", "target", "firmware", "source", "output", "output_dir"}
)
_SECRET_ENV_PARTS = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "API_KEY",
    "ACCESS_KEY",
    "PRIVATE_KEY",
    "CREDENTIAL",
)
_PROXY_KEYS = {
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy",
}


class LocalCliExecutionError(RuntimeError):
    """A fail-closed local execution refusal or bounded process failure."""


@dataclass(frozen=True)
class CliOutputArtifact:
    relative_path: str
    size_bytes: int
    sha256: str = ""


@dataclass(frozen=True)
class CliProcessResult:
    returncode: int
    stdout: bytes = field(default=b"", repr=False)
    stderr: bytes = field(default=b"", repr=False)
    timed_out: bool = False


@dataclass(frozen=True)
class LocalCliExecution:
    tool: str
    method: str
    returncode: int
    timed_out: bool
    provenance: dict
    stdout_sha256: str
    stderr_sha256: str
    stdout_size: int
    stderr_size: int
    outputs: tuple[CliOutputArtifact, ...]
    workspace: str
    retained_workspace: bool
    raw_stdout: bytes = field(default=b"", repr=False)
    raw_stderr: bytes = field(default=b"", repr=False)
    output_file: bytes = field(default=b"", repr=False)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


Runner = Callable[[list[str], Path, float, dict[str, str], int], CliProcessResult]


def _hash_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hash_file(path: Path, *, maximum_bytes: int) -> str:
    if path.stat().st_size > maximum_bytes:
        return ""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _local_path(value: str | Path | None, label: str) -> Path | None:
    if value is None:
        return None
    path = Path(value).expanduser().resolve()
    if not path.exists():
        raise LocalCliExecutionError(f"{label} must be an existing local path")
    return path


def _template_fields(template: tuple[str, ...]) -> set[str]:
    formatter = string.Formatter()
    fields: set[str] = set()
    for token in template:
        for _literal, field_name, _format_spec, _conversion in formatter.parse(str(token)):
            if field_name:
                fields.add(field_name)
    unknown = fields - _ALLOWED_PLACEHOLDERS
    if unknown:
        raise LocalCliExecutionError(
            f"unsupported command placeholder(s): {', '.join(sorted(unknown))}"
        )
    return fields


def _sanitized_env(workspace: Path) -> dict[str, str]:
    """Build a child environment without inherited credentials or usable HTTP proxies."""
    output: dict[str, str] = {}
    for key, value in os.environ.items():
        upper = key.upper()
        if key in _PROXY_KEYS or any(part in upper for part in _SECRET_ENV_PARTS):
            continue
        output[key] = value
    home = workspace / "home"
    tmp = workspace / "tmp"
    cache = workspace / "cache"
    for path in (home, tmp, cache):
        path.mkdir(parents=True, exist_ok=True)
    output.update(
        HOME=str(home),
        TMPDIR=str(tmp),
        TEMP=str(tmp),
        TMP=str(tmp),
        XDG_CACHE_HOME=str(cache),
        HTTP_PROXY="http://127.0.0.1:9",
        HTTPS_PROXY="http://127.0.0.1:9",
        ALL_PROXY="http://127.0.0.1:9",
        NO_PROXY="",
        DO_NOT_TRACK="1",
        SEMGREP_ENABLE_VERSION_CHECK="0",
        SEMGREP_SEND_METRICS="off",
    )
    return output


def _posix_limiter(timeout: float, maximum_output_bytes: int):
    if os.name != "posix":
        return None

    def _limit() -> None:
        try:
            import resource

            cpu = max(1, min(3600, int(timeout) + 5))
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
            resource.setrlimit(
                resource.RLIMIT_FSIZE,
                (maximum_output_bytes, maximum_output_bytes),
            )
            # Prevent creating an unbounded number of child processes without imposing a tiny
            # limit that would break Java/Ghidra-style analyzers.
            soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
            if hard != resource.RLIM_INFINITY:
                resource.setrlimit(resource.RLIMIT_NPROC, (min(soft, 256), hard))
        except Exception:
            # Wall-time/output caps remain enforced by the parent even if a platform refuses a
            # particular rlimit. Execution provenance records the platform, not a false claim.
            return

    return _limit


def _default_runner(
    argv: list[str],
    workspace: Path,
    timeout: float,
    env: dict[str, str],
    maximum_output_bytes: int,
) -> CliProcessResult:
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
            preexec_fn=_posix_limiter(timeout, maximum_output_bytes),
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
    stdout = stdout_path.read_bytes()[:maximum_output_bytes]
    stderr = stderr_path.read_bytes()[:maximum_output_bytes]
    return CliProcessResult(returncode, stdout, stderr, timed_out)


def _output_manifest(
    workspace: Path,
    *,
    maximum_files: int,
    maximum_hash_bytes: int,
) -> tuple[CliOutputArtifact, ...]:
    excluded = {"stdout.bin", "stderr.bin"}
    rows: list[CliOutputArtifact] = []
    for path in sorted(workspace.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(workspace).as_posix()
        if relative in excluded or relative.startswith(("home/", "tmp/", "cache/")):
            continue
        rows.append(
            CliOutputArtifact(
                relative_path=relative,
                size_bytes=path.stat().st_size,
                sha256=_hash_file(path, maximum_bytes=maximum_hash_bytes),
            )
        )
        if len(rows) >= maximum_files:
            break
    return tuple(rows)


def execute_local_cli_method(
    method: PlannedMethod,
    *,
    artifact_path: str | Path | None = None,
    target_path: str | Path | None = None,
    firmware_path: str | Path | None = None,
    source_path: str | Path | None = None,
    workspace_root: str | Path | None = None,
    retain_workspace: bool = False,
    timeout: float = 300.0,
    maximum_output_bytes: int = 16 * 1024 * 1024,
    maximum_manifest_files: int = 500,
    runtime_manager: ToolRuntimeManager | None = None,
    pins: dict[str, ToolPin] | None = None,
    runner: Runner | None = None,
) -> LocalCliExecution:
    """Execute one READY offline method against explicitly supplied local inputs."""
    if not bool(getattr(method, "local_only", False)):
        raise LocalCliExecutionError("method is not declared local_only")
    if bool(getattr(method, "requires_network", False)):
        raise LocalCliExecutionError("network-capable methods are forbidden in local CLI executor")
    if bool(getattr(method, "state_change_possible", False)):
        raise LocalCliExecutionError("state-changing methods require the separate approval path")

    template = tuple(getattr(method, "command_template", ()) or ())
    if not template:
        raise LocalCliExecutionError("method has no executable argv contract")
    binary = method_binary(method)
    if not binary:
        raise LocalCliExecutionError("method has no stable external CLI binary contract")

    timeout = float(timeout)
    if not 0.1 <= timeout <= 3600:
        raise LocalCliExecutionError("timeout must be in [0.1, 3600] seconds")
    if not 1024 <= int(maximum_output_bytes) <= 512 * 1024 * 1024:
        raise LocalCliExecutionError("maximum_output_bytes is outside the allowed range")

    inputs = {
        "artifact": _local_path(artifact_path, "artifact"),
        "target": _local_path(target_path, "target"),
        "firmware": _local_path(firmware_path, "firmware"),
        "source": _local_path(source_path, "source"),
    }
    fields = _template_fields(template)
    missing = sorted(field for field in fields if field in inputs and inputs[field] is None)
    if missing:
        raise LocalCliExecutionError(
            f"missing local input(s): {', '.join(missing)}"
        )

    manager = runtime_manager or ToolRuntimeManager()
    configured_pins = pins if pins is not None else load_tool_pins()
    pin = (
        configured_pins.get(str(method.tool))
        or configured_pins.get(str(method.tool).lower())
        or configured_pins.get(binary)
    )
    record = manager.inspect(name=str(method.tool), binary=binary, pin=pin, refresh=True)
    if record.status is not ToolRuntimeStatus.READY:
        raise LocalCliExecutionError(
            f"tool runtime is {record.status.value}: {record.reason}"
        )

    root = Path(workspace_root).expanduser().resolve() if workspace_root else None
    if root is not None:
        root.mkdir(parents=True, exist_ok=True)
    workspace = Path(tempfile.mkdtemp(prefix="aegis-asset-", dir=str(root) if root else None))
    output_file = workspace / "result.out"
    output_dir = workspace / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    values = {
        **{key: str(value) if value is not None else "" for key, value in inputs.items()},
        "output": str(output_file),
        "output_dir": str(output_dir),
    }

    argv = [str(token).format_map(values) for token in template]
    argv[0] = record.resolved_path
    env = _sanitized_env(workspace)
    process_runner = runner or _default_runner
    try:
        process = process_runner(
            argv,
            workspace,
            timeout,
            env,
            int(maximum_output_bytes),
        )
        stdout = bytes(process.stdout[:maximum_output_bytes])
        stderr = bytes(process.stderr[:maximum_output_bytes])
        output_bytes = (
            output_file.read_bytes()[:maximum_output_bytes]
            if output_file.is_file()
            else b""
        )
        manifest = _output_manifest(
            workspace,
            maximum_files=max(1, int(maximum_manifest_files)),
            maximum_hash_bytes=int(maximum_output_bytes),
        )
        runtime_provenance = provenance(record, argv)
        runtime_provenance.update(
            {
                "execution_mode": "local_cli",
                "requires_network": False,
                "state_change_possible": False,
                "shell": False,
                "platform": os.name,
                "timeout_seconds": timeout,
            }
        )
        result = LocalCliExecution(
            tool=str(method.tool),
            method=str(method.method),
            returncode=int(process.returncode),
            timed_out=bool(process.timed_out),
            provenance=runtime_provenance,
            stdout_sha256=_hash_bytes(stdout),
            stderr_sha256=_hash_bytes(stderr),
            stdout_size=len(stdout),
            stderr_size=len(stderr),
            outputs=manifest,
            workspace=str(workspace) if retain_workspace else "",
            retained_workspace=retain_workspace,
            raw_stdout=stdout,
            raw_stderr=stderr,
            output_file=output_bytes,
        )
    except Exception:
        if not retain_workspace:
            shutil.rmtree(workspace, ignore_errors=True)
        raise

    if not retain_workspace:
        shutil.rmtree(workspace, ignore_errors=True)
    return result


def cleanup_local_cli_execution(execution: LocalCliExecution) -> None:
    """Remove an explicitly retained executor workspace."""
    if not execution.retained_workspace or not execution.workspace:
        return
    path = Path(execution.workspace).resolve()
    if path.name.startswith("aegis-asset-"):
        shutil.rmtree(path, ignore_errors=True)
