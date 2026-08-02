"""Safe external process runner (Master Prompt §6; Phase 1 safe process runner).

Runs a tool as an **argument array with no shell**, in an isolated working
directory with a **minimal allowlisted environment**. Secrets are resolved into
protected files and referenced by env var — **never** placed in argv, logs, or
events. Output is **streamed and bounded** (byte / line / event caps) so a flood
cannot exhaust memory. Wall-time and idle-time deadlines and (on POSIX) CPU /
memory / open-file / process rlimits bound the work. On cancellation or timeout
the **entire process tree** is terminated (POSIX process group / Windows
``taskkill /T``). Exit status is classified without trusting stderr text.

Cross-platform: rlimits are POSIX-only (production is Linux); the wall/idle
deadlines, output caps, cancellation, and tree termination work on both.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from enum import Enum


class ProcessOutcome(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    OUTPUT_LIMIT = "output_limit"
    START_ERROR = "start_error"


class BinaryVerificationError(RuntimeError):
    pass


@dataclass
class ProcessLimits:
    wall_seconds: float = 60.0
    idle_seconds: float | None = None
    max_stdout_bytes: int = 8 * 1024 * 1024
    max_stderr_bytes: int = 1 * 1024 * 1024
    max_line_bytes: int = 64 * 1024
    max_events: int | None = None
    memory_bytes: int | None = None  # POSIX RLIMIT_AS
    cpu_seconds: int | None = None   # POSIX RLIMIT_CPU
    open_files: int | None = None    # POSIX RLIMIT_NOFILE
    processes: int | None = None     # POSIX RLIMIT_NPROC


@dataclass
class ProcessResult:
    outcome: ProcessOutcome
    exit_code: int | None
    lines: list[str] = field(default_factory=list)
    stderr: str = ""
    truncated: bool = False
    duration_s: float = 0.0

    @property
    def ok(self) -> bool:
        return self.outcome == ProcessOutcome.SUCCEEDED


class CancelToken:
    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()


# OS-essential env vars kept even under a strict allowlist (so the binary starts).
_OS_ESSENTIAL = ("PATH",) + (
    ("SystemRoot", "SYSTEMROOT", "ComSpec", "PATHEXT", "WINDIR", "TEMP", "TMP")
    if os.name == "nt"
    else ()
)


def verify_binary(path: str, expected_sha256: str) -> str:
    """Return the file's SHA-256, raising if it does not match ``expected_sha256``."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    actual = h.hexdigest()
    if actual != expected_sha256:
        raise BinaryVerificationError(f"binary checksum mismatch for {path}")
    return actual


class SafeProcessRunner:
    def __init__(self, *, env_allowlist: tuple[str, ...] = ("LANG", "LC_ALL", "TZ")) -> None:
        self._allowlist = env_allowlist

    def _build_env(self, extra: dict[str, str]) -> dict[str, str]:
        env: dict[str, str] = {}
        for key in (*self._allowlist, *_OS_ESSENTIAL):
            if key in os.environ:
                env[key] = os.environ[key]
        env.update(extra)  # secret file *paths* only
        return env

    def run(
        self,
        argv: list[str],
        *,
        limits: ProcessLimits | None = None,
        cwd: str | None = None,
        secrets: dict[str, str] | None = None,
        cancel: CancelToken | None = None,
        on_line=None,
    ) -> ProcessResult:
        limits = limits or ProcessLimits()
        owns_workdir = cwd is None
        workdir = cwd or tempfile.mkdtemp(prefix="aegis-proc-")
        start = time.monotonic()
        try:
            secret_env = self._write_secrets(workdir, secrets)
            env = self._build_env(secret_env)
            try:
                proc = subprocess.Popen(
                    argv, cwd=workdir, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    **self._spawn_kwargs(limits),
                )
            except (FileNotFoundError, OSError) as exc:
                return ProcessResult(ProcessOutcome.START_ERROR, None, [], str(exc), False,
                                     time.monotonic() - start)
            return self._supervise(proc, limits, cancel, on_line, start)
        finally:
            if owns_workdir:
                shutil.rmtree(workdir, ignore_errors=True)  # removes secret files too

    # -- internals --

    def _write_secrets(self, workdir: str, secrets: dict[str, str] | None) -> dict[str, str]:
        secret_env: dict[str, str] = {}
        for name, value in (secrets or {}).items():
            path = os.path.join(workdir, f".secret_{name}")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(value)
            if os.name != "nt":
                os.chmod(path, 0o600)
            secret_env[f"AEGIS_SECRET_{name.upper()}"] = path
        return secret_env

    def _spawn_kwargs(self, limits: ProcessLimits) -> dict:
        if os.name == "nt":
            return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        kwargs: dict = {"start_new_session": True}
        preexec = _rlimit_preexec(limits)
        if preexec is not None:
            kwargs["preexec_fn"] = preexec
        return kwargs

    def _supervise(self, proc, limits, cancel, on_line, start) -> ProcessResult:
        lines: list[str] = []
        state = {"last_output": time.monotonic()}
        overflow = threading.Event()
        stderr_buf = bytearray()

        def sink(line: str) -> None:
            lines.append(line)
            state["last_output"] = time.monotonic()
            if on_line is not None:
                on_line(line)

        def read_stdout() -> None:
            if _read_bounded(proc.stdout, limits.max_stdout_bytes, limits.max_line_bytes, limits.max_events, sink):
                overflow.set()

        def read_stderr() -> None:
            while True:
                chunk = proc.stderr.read(65536)
                if not chunk:
                    break
                room = limits.max_stderr_bytes - len(stderr_buf)
                if room > 0:
                    stderr_buf.extend(chunk[:room])

        t_out = threading.Thread(target=read_stdout, daemon=True)
        t_err = threading.Thread(target=read_stderr, daemon=True)
        t_out.start()
        t_err.start()

        outcome = None
        while True:
            if proc.poll() is not None:
                outcome = ProcessOutcome.SUCCEEDED if proc.returncode == 0 else ProcessOutcome.FAILED
                break
            now = time.monotonic()
            if cancel is not None and cancel.cancelled:
                outcome = ProcessOutcome.CANCELLED
                break
            if now - start > limits.wall_seconds:
                outcome = ProcessOutcome.TIMED_OUT
                break
            if limits.idle_seconds is not None and now - state["last_output"] > limits.idle_seconds:
                outcome = ProcessOutcome.TIMED_OUT
                break
            if overflow.is_set():
                outcome = ProcessOutcome.OUTPUT_LIMIT
                break
            time.sleep(0.03)

        exit_code = proc.returncode
        if outcome in (ProcessOutcome.CANCELLED, ProcessOutcome.TIMED_OUT, ProcessOutcome.OUTPUT_LIMIT):
            _terminate_tree(proc)
            exit_code = None
        try:
            proc.wait(timeout=5)
        except Exception:
            _terminate_tree(proc)
        t_out.join(2)
        t_err.join(2)
        return ProcessResult(
            outcome=outcome, exit_code=exit_code, lines=lines,
            stderr=stderr_buf.decode("utf-8", "replace"), truncated=overflow.is_set(),
            duration_s=time.monotonic() - start,
        )


def _read_bounded(stream, max_bytes: int, max_line_bytes: int, max_events, sink) -> bool:
    """Stream lines to ``sink``; return True if an output limit was hit."""
    total = 0
    events = 0
    buf = bytearray()
    while True:
        chunk = stream.read(65536)
        if not chunk:
            break
        total += len(chunk)
        buf.extend(chunk)
        while True:
            nl = buf.find(b"\n")
            if nl == -1:
                break
            line = bytes(buf[:nl])
            del buf[: nl + 1]
            if line.endswith(b"\r"):  # normalise CRLF
                line = line[:-1]
            if len(line) > max_line_bytes:
                line = line[:max_line_bytes]
            sink(line.decode("utf-8", "replace"))
            events += 1
            if max_events is not None and events >= max_events:
                return True
        if total > max_bytes:
            return True
    if buf:
        tail = bytes(buf[:max_line_bytes]).rstrip(b"\r\n")
        if tail:
            sink(tail.decode("utf-8", "replace"))
    return False


def _terminate_tree(proc) -> None:
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=10)
        else:
            import signal

            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                time.sleep(0.2)
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _rlimit_preexec(limits: ProcessLimits):
    if os.name == "nt":
        return None
    if not any([limits.cpu_seconds, limits.memory_bytes, limits.open_files, limits.processes]):
        return None
    import resource

    def apply() -> None:  # pragma: no cover - runs in the child process
        if limits.cpu_seconds:
            resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
        if limits.memory_bytes:
            resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
        if limits.open_files:
            resource.setrlimit(resource.RLIMIT_NOFILE, (limits.open_files, limits.open_files))
        if limits.processes:
            resource.setrlimit(resource.RLIMIT_NPROC, (limits.processes, limits.processes))

    return apply
