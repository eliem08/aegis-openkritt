"""Runtime health, pinning and provenance for external security tools.

Aegis never assumes that a registry entry means a scanner is executable. This module resolves
an installed binary, fingerprints the exact executable, performs a bounded non-target version
probe (or accepts caller-supplied trusted local metadata), checks optional pins, and returns an
explicit status before any scan is considered.

The manager never uses ``shell=True`` and never sends a target to a tool during health checks.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable


class ToolRuntimeStatus(str, Enum):
    READY = "ready"
    UNAVAILABLE = "unavailable"
    STALE = "stale"
    QUARANTINED = "quarantined"


@dataclass(frozen=True)
class ToolPin:
    """Optional immutable expectations for a worker tool installation."""

    sha256: str = ""
    version_contains: str = ""


@dataclass(frozen=True)
class ToolRuntimeRecord:
    name: str
    binary: str
    resolved_path: str
    version: str
    sha256: str
    status: ToolRuntimeStatus
    reason: str
    checked_at: str

    @property
    def ready(self) -> bool:
        return self.status is ToolRuntimeStatus.READY

    def as_dict(self) -> dict:
        data = asdict(self)
        data["status"] = self.status.value
        return data


Resolver = Callable[[str], str | None]
Runner = Callable[[list[str], float], tuple[int, str, str]]


def load_tool_pins(path: str | Path | None = None) -> dict[str, ToolPin]:
    """Load optional worker pins from JSON.

    File shape::

        {"semgrep": {"sha256": "<64 hex>", "version_contains": "1.99"}}

    An explicitly configured but malformed file raises ``ValueError`` instead of silently
    disabling pin enforcement. No file configured means no pins.
    """
    configured = str(path or os.environ.get("AEGIS_TOOL_PINS_FILE", "")).strip()
    if not configured:
        # P0.4: pins are optional in development but MANDATORY in production/bug-bounty mode —
        # unattended Jarvis must never run an unpinned (unverified) executable. Fail closed.
        if _pins_required():
            raise RuntimeError(
                "scanner pins are mandatory in production/bug-bounty mode: set "
                "AEGIS_TOOL_PINS_FILE (or unset AEGIS_TOOL_PINS_REQUIRED / AEGIS_MODE for dev)")
        return {}
    pin_path = Path(configured)
    if not pin_path.is_file():
        raise ValueError(f"tool pin file does not exist: {pin_path}")
    try:
        payload = json.loads(pin_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("tool pin file is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("tool pin file must contain an object keyed by tool name")

    pins: dict[str, ToolPin] = {}
    for raw_name, raw_pin in payload.items():
        name = str(raw_name).strip()
        if not name or not isinstance(raw_pin, dict):
            raise ValueError("every tool pin must be a named object")
        sha = str(raw_pin.get("sha256") or "").strip().lower()
        marker = str(raw_pin.get("version_contains") or "").strip()
        if sha and (len(sha) != 64 or any(char not in "0123456789abcdef" for char in sha)):
            raise ValueError(f"invalid sha256 pin for {name}")
        if len(marker) > 120:
            raise ValueError(f"version marker too long for {name}")
        pins[name] = ToolPin(sha256=sha, version_contains=marker)
    return pins


def resolve_binary(binary: str) -> str | None:
    """Resolve PATH plus the running interpreter's scripts directory."""
    found = shutil.which(binary)
    if found:
        return str(Path(found).resolve())
    scripts = Path(sys.executable).parent
    for name in (binary, binary + ".exe", binary + ".cmd", binary + ".bat"):
        candidate = scripts / name
        if candidate.is_file():
            return str(candidate.resolve())
    return None


def _pins_required() -> bool:
    if os.environ.get("AEGIS_TOOL_PINS_REQUIRED", "").strip().lower() in ("1", "true", "yes"):
        return True
    return os.environ.get("AEGIS_MODE", "").strip().lower() in ("production", "bug-bounty", "bounty")


def _health_env() -> dict[str, str]:
    """Environment for the health/version probe.

    P0.4: the probe must NOT inherit credentials — an unpinned malicious binary discovered on
    PATH could otherwise receive tokens during an innocent ``scanner --version`` call. Reuse the
    same credential/proxy scrubbing the execution path uses (imported lazily to avoid a cycle),
    and point proxies at a dead loopback address.
    """
    try:
        from .jarvis.asset_cli_executor import _PROXY_KEYS, _SECRET_ENV_PARTS
    except Exception:  # pragma: no cover - fall back to a conservative built-in denylist
        _PROXY_KEYS = {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"}
        _SECRET_ENV_PARTS = ("TOKEN", "PASSWORD", "SECRET", "API_KEY", "APIKEY", "CREDENTIAL",
                             "KEY", "AUTH")
    env: dict[str, str] = {}
    for key, value in os.environ.items():
        upper = key.upper()
        if key in _PROXY_KEYS or any(part in upper for part in _SECRET_ENV_PARTS):
            continue
        env[key] = value
    env.update(
        SEMGREP_ENABLE_VERSION_CHECK="0",
        SEMGREP_SEND_METRICS="off",
        DO_NOT_TRACK="1",
        HTTP_PROXY="http://127.0.0.1:9",
        HTTPS_PROXY="http://127.0.0.1:9",
        ALL_PROXY="http://127.0.0.1:9",
        NO_PROXY="",
    )
    return env


def _default_runner(argv: list[str], timeout: float) -> tuple[int, str, str]:
    completed = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=_health_env(),
    )
    return completed.returncode, completed.stdout or "", completed.stderr or ""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _first_line(stdout: str, stderr: str) -> str:
    text = (stdout.strip() or stderr.strip()).replace("\x00", "")
    return text.splitlines()[0][:240] if text else ""


class ToolRuntimeManager:
    """Inspect installed tools and produce immutable health/provenance records."""

    def __init__(self, *, resolver: Resolver | None = None, runner: Runner | None = None,
                 version_timeout: float = 5.0) -> None:
        self._resolver = resolver or resolve_binary
        self._runner = runner or _default_runner
        self._timeout = max(0.1, float(version_timeout))
        self._cache: dict[tuple[str, str, str, str, str], ToolRuntimeRecord] = {}

    def resolve(self, binary: str) -> str | None:
        """Expose the configured resolver for adapters with non-standard version metadata."""
        resolved = self._resolver(binary)
        return str(Path(resolved).resolve()) if resolved else None

    def inspect(self, *, name: str, binary: str, pin: ToolPin | None = None,
                refresh: bool = False, version_override: str = "") -> ToolRuntimeRecord:
        pin = pin or ToolPin()
        trusted_version = str(version_override or "").strip().replace("\x00", " ")[:240]
        key = (name, binary, pin.sha256.lower(), pin.version_contains, trusted_version)
        if not refresh and key in self._cache:
            return self._cache[key]

        now = datetime.now(UTC).isoformat()
        resolved = self.resolve(binary)
        if not resolved:
            record = ToolRuntimeRecord(
                name=name,
                binary=binary,
                resolved_path="",
                version="",
                sha256="",
                status=ToolRuntimeStatus.UNAVAILABLE,
                reason="binary not found",
                checked_at=now,
            )
            self._cache[key] = record
            return record

        path = Path(resolved)
        try:
            if not path.is_file():
                raise OSError("resolved path is not a regular file")
            digest = _sha256(path)
        except OSError as exc:
            record = ToolRuntimeRecord(
                name=name,
                binary=binary,
                resolved_path=str(path),
                version="",
                sha256="",
                status=ToolRuntimeStatus.QUARANTINED,
                reason=f"fingerprint failed: {type(exc).__name__}",
                checked_at=now,
            )
            self._cache[key] = record
            return record

        if pin.sha256 and digest.lower() != pin.sha256.strip().lower():
            record = ToolRuntimeRecord(
                name=name,
                binary=binary,
                resolved_path=str(path),
                version="",
                sha256=digest,
                status=ToolRuntimeStatus.QUARANTINED,
                reason="executable digest does not match configured pin",
                checked_at=now,
            )
            self._cache[key] = record
            return record

        version = trusted_version or self._probe_version(str(path))
        if not version:
            status = ToolRuntimeStatus.STALE
            reason = "version probe did not produce a bounded healthy response"
        elif pin.version_contains and pin.version_contains.lower() not in version.lower():
            status = ToolRuntimeStatus.STALE
            reason = "installed version does not satisfy configured version marker"
        else:
            status = ToolRuntimeStatus.READY
            reason = "healthy"

        record = ToolRuntimeRecord(
            name=name,
            binary=binary,
            resolved_path=str(path),
            version=version,
            sha256=digest,
            status=status,
            reason=reason,
            checked_at=now,
        )
        self._cache[key] = record
        return record

    def _probe_version(self, resolved: str) -> str:
        binary_name = Path(resolved).name.casefold().removesuffix(".exe")
        extra_probes = {
            # Binwalk 2.x treats --version as an input filename. Its bounded help
            # header is the upstream-supported source of version provenance.
            "binwalk": (("-h",),),
            # jsluice is pinned by immutable source commit and intentionally has no
            # version subcommand. Its bounded upstream help header is its supported
            # non-target health probe; the executable digest supplies identity.
            "jsluice": (("--help",),),
            # ssh-audit exposes argparse help but no --version flag.  Keep the
            # probe bounded and non-targeting; the package version is pinned.
            "ssh-audit": (("-h",),),
        }.get(binary_name, ())
        for suffix in (*extra_probes, ("--version",), ("version",), ("-version",)):
            argv = [resolved, *suffix]
            try:
                code, stdout, stderr = self._runner(argv, self._timeout)
            except Exception:
                continue
            line = _first_line(stdout, stderr)
            if code == 0 and line:
                return line
        return ""

    def inspect_tool(self, tool, *, pin: ToolPin | None = None,
                     refresh: bool = False) -> ToolRuntimeRecord:
        return self.inspect(name=str(tool.name), binary=str(tool.binary), pin=pin, refresh=refresh)

    def inventory(self, tools: Iterable, *, pins: dict[str, ToolPin] | None = None,
                  refresh: bool = False) -> tuple[ToolRuntimeRecord, ...]:
        configured = pins or {}
        return tuple(
            self.inspect_tool(tool, pin=configured.get(str(tool.name)), refresh=refresh)
            for tool in tools
        )


def provenance(record: ToolRuntimeRecord, argv: list[str]) -> dict:
    """Sanitized execution provenance to attach to scanner observations."""
    if not argv:
        raise ValueError("argv cannot be empty")
    return {
        "tool": record.name,
        "status": record.status.value,
        "version": record.version,
        "binary_sha256": record.sha256,
        "resolved_path": record.resolved_path,
        "argv": [str(value)[:1000] for value in argv],
    }
