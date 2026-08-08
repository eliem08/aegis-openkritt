"""OS-level networkless wrapper for trusted local scanner CLIs.

The generic asset CLI executor already uses argv arrays, bounded workspaces and sanitized
credentials/proxies. This module adds a stronger Linux production boundary: the scanner process is
started inside Bubblewrap with an unshared network namespace, read-only host root and writable
private Aegis workspace only.

This is intended for scanner binaries themselves; it does not make arbitrary target-provided code
safe to execute. Methods requiring a semantic ``isolated_sandbox`` still need an explicitly
registered backend such as the dedicated Ghidra adapter.
"""

from __future__ import annotations

import os
import signal
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Callable

from ..tool_runtime import ToolPin, ToolRuntimeManager, ToolRuntimeStatus, load_tool_pins
from .asset_cli_executor import (
    CliProcessResult,
    LocalCliExecution,
    execute_local_cli_method,
)
from .asset_deep_capabilities import PlannedMethod


class NetworklessCliError(RuntimeError):
    pass


ProcessRunner = Callable[[list[str], Path, float, dict[str, str], int], CliProcessResult]


def _resolve_bwrap() -> str:
    return os.environ.get("AEGIS_BWRAP_PATH", "").strip() or "bwrap"


def _pin(pins: dict[str, ToolPin], binary: str) -> ToolPin | None:
    return pins.get("bubblewrap") or pins.get(binary)


def _default_process_runner(
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
            env={
                key: value
                for key, value in env.items()
                if key in {"PATH", "LANG", "LC_ALL", "HOME", "TMPDIR"}
            },
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
    return CliProcessResult(
        returncode=returncode,
        stdout=stdout_path.read_bytes()[:maximum_output_bytes],
        stderr=stderr_path.read_bytes()[:maximum_output_bytes],
        timed_out=timed_out,
    )


def _sandbox_argv(
    bwrap_path: str,
    scanner_argv: list[str],
    workspace: Path,
    env: dict[str, str],
) -> list[str]:
    home = workspace / "home"
    home.mkdir(parents=True, exist_ok=True)
    path_value = env.get("PATH", "/usr/local/bin:/usr/bin:/bin")
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
        "--setenv", "DO_NOT_TRACK", "1",
        "--setenv", "SEMGREP_ENABLE_VERSION_CHECK", "0",
        "--setenv", "SEMGREP_SEND_METRICS", "off",
        "--",
        *scanner_argv,
    ]
    return argv


def execute_networkless_cli_method(
    method: PlannedMethod,
    *,
    runtime_manager: ToolRuntimeManager | None = None,
    pins: dict[str, ToolPin] | None = None,
    process_runner: ProcessRunner | None = None,
    **kwargs,
) -> LocalCliExecution:
    """Execute an ordinary local-only scanner inside a Bubblewrap network namespace."""
    if os.name != "posix" and process_runner is None:
        raise NetworklessCliError("production networkless CLI backend requires Linux/POSIX")
    manager = runtime_manager or ToolRuntimeManager()
    configured_pins = pins if pins is not None else load_tool_pins()
    bwrap_binary = _resolve_bwrap()
    bwrap = manager.inspect(
        name="bubblewrap",
        binary=bwrap_binary,
        pin=_pin(configured_pins, bwrap_binary),
        refresh=True,
    )
    if bwrap.status is not ToolRuntimeStatus.READY:
        raise NetworklessCliError(
            f"Bubblewrap runtime is {bwrap.status.value}: {bwrap.reason}"
        )
    low_level = process_runner or _default_process_runner

    def runner(scanner_argv, workspace, timeout, env, maximum_output_bytes):
        sandbox_argv = _sandbox_argv(
            bwrap.resolved_path,
            list(scanner_argv),
            workspace,
            env,
        )
        return low_level(
            sandbox_argv,
            workspace,
            timeout,
            env,
            maximum_output_bytes,
        )

    execution = execute_local_cli_method(
        method,
        runtime_manager=manager,
        pins=configured_pins,
        runner=runner,
        **kwargs,
    )
    provenance = dict(execution.provenance)
    provenance["network_sandbox"] = {
        "tool": "bubblewrap",
        "version": bwrap.version,
        "binary_sha256": bwrap.sha256,
        "unshare_all": True,
        "network_shared": False,
        "host_root": "read_only",
        "writable_workspace_only": True,
    }
    provenance["network_enforcement"] = "kernel_namespace"
    return replace(execution, provenance=provenance)


__all__ = ["NetworklessCliError", "execute_networkless_cli_method"]
