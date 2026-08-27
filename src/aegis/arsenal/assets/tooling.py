"""Detect external binaries and route Linux-only tools through ``Dockerfile.arsenal``.

The operator's workstation is Windows, where ``semgrep-core``, ``slither``, ``nmap``
and several language-specific scanners are missing or unreliable. The repository
already ships ``Dockerfile.arsenal`` (a Linux image with the full scanner set), so
this module answers one question per tool: *can I run it here, can I run it in the
container, or can I not run it at all?* — and returns that answer instead of
crashing or, worse, returning an empty result that reads like a clean scan.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Sequence

#: The image ``Dockerfile.arsenal`` builds. Overridable for a custom tag.
ARSENAL_IMAGE = os.environ.get("AEGIS_ARSENAL_IMAGE", "aegis-arsenal")

#: Tools known not to work natively on Windows; routed to the container when possible.
LINUX_ONLY_TOOLS: frozenset[str] = frozenset({
    "semgrep", "semgrep-core", "slither", "mythril", "myth", "brakeman", "psalm",
    "gosec", "osv-scanner", "nmap", "syft", "grype", "trivy", "testssl.sh",
})

#: Tools implemented in pure Python inside Aegis; always available, never shelled out.
INTERNAL_TOOLS: frozenset[str] = frozenset({
    "aegis-openapi-parser", "aegis-policy-parser", "aegis-binary-triage", "aegis-strings",
    "aegis-asar", "aegis-contract-patterns", "aegis-llm-lab", "aegis-output-oracle",
    "aegis-authz-matrix", "aegis-bola-probe", "aegis-asset-triage", "stdlib-http",
    "stdlib-ssl", "stdlib-resolver", "crt.sh",
})


class ToolLocation(str, Enum):
    NATIVE = "native"
    CONTAINER = "container"
    INTERNAL = "internal"
    MISSING = "missing"


@dataclass(frozen=True, slots=True)
class ToolAvailability:
    name: str
    location: ToolLocation
    path: str = ""
    version: str = ""
    reason: str = ""

    @property
    def usable(self) -> bool:
        return self.location is not ToolLocation.MISSING

    def command(self, arguments: Sequence[str], *, mounts: Sequence[str] = ()) -> list[str]:
        """Build the argv that actually invokes the tool where it lives."""
        if self.location is ToolLocation.NATIVE:
            return [self.path or self.name, *arguments]
        if self.location is ToolLocation.CONTAINER:
            volumes: list[str] = []
            for mount in mounts:
                resolved = Path(mount).resolve()
                volumes.extend(["-v", f"{resolved}:{resolved.as_posix()}:ro"])
            return ["docker", "run", "--rm", "--network", "none", *volumes,
                    ARSENAL_IMAGE, self.name, *arguments]
        raise RuntimeError(
            f"tool {self.name!r} is {self.location.value}; it has no external command"
        )

    def document(self) -> dict[str, Any]:
        value = asdict(self)
        value["location"] = self.location.value
        return value


Which = Callable[[str], str | None]
Runner = Callable[[list[str], float], tuple[int, str, str]]


def _run(argv: list[str], timeout: float) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, never shell=True
            argv, capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, "", f"{type(exc).__name__}: {exc}"
    return completed.returncode, completed.stdout or "", completed.stderr or ""


class ToolResolver:
    """Caching availability lookup across native PATH and the arsenal container."""

    def __init__(
        self,
        *,
        which: Which = shutil.which,
        runner: Runner = _run,
        allow_container: bool = True,
        version_timeout: float = 10.0,
    ) -> None:
        self._which = which
        self._runner = runner
        self._allow_container = allow_container
        self._version_timeout = version_timeout
        self._cache: dict[str, ToolAvailability] = {}
        self._docker: bool | None = None

    def docker_available(self) -> bool:
        if self._docker is None:
            if not self._allow_container or not self._which("docker"):
                self._docker = False
            else:
                code, _, _ = self._runner(["docker", "image", "inspect", ARSENAL_IMAGE], 20.0)
                self._docker = code == 0
        return self._docker

    def resolve(self, name: str, *, version_flag: str = "--version") -> ToolAvailability:
        if name in self._cache:
            return self._cache[name]
        self._cache[name] = self._resolve(name, version_flag)
        return self._cache[name]

    def _resolve(self, name: str, version_flag: str) -> ToolAvailability:
        if name in INTERNAL_TOOLS:
            return ToolAvailability(name, ToolLocation.INTERNAL, reason="implemented in-process")
        path = self._which(name)
        if path:
            code, out, err = self._runner([path, version_flag], self._version_timeout)
            version = (out or err).strip().splitlines()[0] if (out or err).strip() else ""
            if code == 0 or version:
                return ToolAvailability(name, ToolLocation.NATIVE, path, version)
            return ToolAvailability(
                name, ToolLocation.NATIVE, path, "",
                reason="binary resolved but the version probe did not report cleanly",
            )
        if self.docker_available():
            return ToolAvailability(
                name, ToolLocation.CONTAINER, reason=f"routed through {ARSENAL_IMAGE}",
            )
        hint = (
            f"not on PATH and the {ARSENAL_IMAGE} image is unavailable; "
            "build it with `docker build -f Dockerfile.arsenal -t aegis-arsenal .`"
            if name in LINUX_ONLY_TOOLS
            else "not on PATH"
        )
        return ToolAvailability(name, ToolLocation.MISSING, reason=hint)

    def first_available(self, names: Sequence[str]) -> ToolAvailability | None:
        """Return the first usable tool from a preference-ordered list."""
        for name in names:
            candidate = self.resolve(name)
            if candidate.usable:
                return candidate
        return None

    def run(
        self, tool: ToolAvailability, arguments: Sequence[str], *,
        mounts: Sequence[str] = (), timeout: float = 300.0,
    ) -> tuple[int, str, str]:
        """Execute an external tool, or report its absence rather than raising."""
        if not tool.usable:
            return 1, "", tool.reason or f"{tool.name} is unavailable"
        return self._runner(tool.command(arguments, mounts=mounts), timeout)


__all__ = [
    "ARSENAL_IMAGE",
    "INTERNAL_TOOLS",
    "LINUX_ONLY_TOOLS",
    "ToolAvailability",
    "ToolLocation",
    "ToolResolver",
]
