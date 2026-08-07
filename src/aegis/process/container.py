"""Fail-closed construction of hardened, digest-pinned Docker invocations.

This module only builds an argv array; :class:`SafeProcessRunner` still owns
process supervision, output limits, cancellation, and secret-safe environment
handling. Keeping construction pure makes every isolation flag reviewable and
prevents adapters from widening the runtime profile.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from aegis.supply import verify_image_pin


class ContainerPolicyError(ValueError):
    """The requested container invocation would weaken the approved profile."""


@dataclass(frozen=True)
class ContainerLimits:
    cpus: float = 1.0
    memory_bytes: int = 1024 * 1024 * 1024
    pids: int = 128
    tmpfs_bytes: int = 64 * 1024 * 1024

    def validate(self) -> None:
        if not 0 < self.cpus <= 8:
            raise ContainerPolicyError("container CPUs must be in (0, 8]")
        if not 64 * 1024 * 1024 <= self.memory_bytes <= 16 * 1024 * 1024 * 1024:
            raise ContainerPolicyError("container memory must be between 64 MiB and 16 GiB")
        if not 16 <= self.pids <= 1024:
            raise ContainerPolicyError("container PID limit must be between 16 and 1024")
        if not 8 * 1024 * 1024 <= self.tmpfs_bytes <= 1024 * 1024 * 1024:
            raise ContainerPolicyError("container tmpfs must be between 8 MiB and 1 GiB")


@dataclass(frozen=True)
class ReadOnlyMount:
    source: str
    destination: str
    sha256: str


class HardenedDockerCommandBuilder:
    """Build one no-egress, non-root, read-only Docker command.

    Repository paths must be descendants of ``repository_root``. Additional
    read-only mounts (for a rule bundle or offline vulnerability DB) must be
    descendants of one of ``approved_mount_roots`` and cannot shadow sensitive
    container paths.
    """

    _FORBIDDEN_DESTINATIONS = frozenset({
        "/", "/src", "/proc", "/sys", "/dev", "/etc", "/var/run",
        "/var/run/docker.sock",
    })

    def __init__(
        self,
        repository_root: str,
        *,
        approved_mount_roots: tuple[str, ...] = (),
        docker_executable: str = "docker",
        uid: int = 65532,
        gid: int = 65532,
        limits: ContainerLimits | None = None,
    ) -> None:
        self.repository_root = self._existing_directory(repository_root, "repository root")
        self.approved_mount_roots = tuple(
            self._existing_directory(path, "approved mount root")
            for path in approved_mount_roots
        )
        if not docker_executable or any(c in docker_executable for c in "\x00\r\n"):
            raise ContainerPolicyError("Docker executable is invalid")
        if uid <= 0 or gid <= 0:
            raise ContainerPolicyError("container UID/GID must be numeric and non-root")
        self.docker_executable = docker_executable
        self.uid = uid
        self.gid = gid
        self.limits = limits or ContainerLimits()
        self.limits.validate()

    def build(
        self,
        *,
        image: str,
        repository: str,
        command: tuple[str, ...] | list[str],
        mounts: tuple[ReadOnlyMount, ...] = (),
    ) -> list[str]:
        digest = verify_image_pin(image)
        if image.lower().split("@sha256:", 1)[1] != digest:
            raise ContainerPolicyError("image digest must use canonical sha256 syntax")
        repo = self._descendant_directory(repository, self.repository_root, "repository")
        argv_command = self._command(command)

        mount_args = [self._mount_arg(repo, "/src")]
        destinations = {"/src"}
        for mount in mounts:
            source = self._approved_mount(mount.source)
            actual_digest = directory_sha256(source)
            if not _valid_sha256(mount.sha256) or actual_digest != mount.sha256.lower():
                raise ContainerPolicyError("read-only mount checksum mismatch")
            destination = self._destination(mount.destination)
            if destination in destinations:
                raise ContainerPolicyError(f"duplicate container mount destination: {destination}")
            destinations.add(destination)
            mount_args.append(self._mount_arg(source, destination))

        limits = self.limits
        argv = [
            self.docker_executable,
            "run",
            "--rm",
            "--pull",
            "never",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            f"{self.uid}:{self.gid}",
            "--pids-limit",
            str(limits.pids),
            "--memory",
            str(limits.memory_bytes),
            "--cpus",
            str(limits.cpus),
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,size={limits.tmpfs_bytes}",
            "--workdir",
            "/src",
            "--env",
            "HOME=/tmp",
            "--env",
            "XDG_CACHE_HOME=/tmp/.cache",
            "--env",
            "TMPDIR=/tmp",
            "--log-driver",
            "none",
        ]
        for mount_arg in mount_args:
            argv.extend(("--mount", mount_arg))
        argv.append(image)
        argv.extend(argv_command)
        return argv

    @staticmethod
    def _existing_directory(value: str, label: str) -> Path:
        try:
            path = Path(value).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ContainerPolicyError(f"{label} does not exist") from exc
        if not path.is_dir():
            raise ContainerPolicyError(f"{label} must be a directory")
        if "," in str(path) or "\x00" in str(path):
            raise ContainerPolicyError(f"{label} contains an unsupported character")
        return path

    def _descendant_directory(self, value: str, root: Path, label: str) -> Path:
        path = self._existing_directory(value, label)
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ContainerPolicyError(f"{label} is outside its approved root") from exc
        if path == root:
            raise ContainerPolicyError(f"{label} must be a child of its approved root")
        return path

    def _approved_mount(self, value: str) -> Path:
        if not self.approved_mount_roots:
            raise ContainerPolicyError("additional read-only mounts are not approved")
        path = self._existing_directory(value, "mount source")
        if not any(self._is_within(path, root) for root in self.approved_mount_roots):
            raise ContainerPolicyError("mount source is outside approved mount roots")
        return path

    @classmethod
    def _destination(cls, value: str) -> str:
        if not isinstance(value, str) or not value.startswith("/"):
            raise ContainerPolicyError("mount destination must be an absolute container path")
        destination = str(PurePosixPath(value))
        if ".." in PurePosixPath(value).parts:
            raise ContainerPolicyError("mount destination cannot traverse parent paths")
        if destination in cls._FORBIDDEN_DESTINATIONS:
            raise ContainerPolicyError(f"mount destination is forbidden: {destination}")
        return destination

    @staticmethod
    def _command(command) -> list[str]:
        if not isinstance(command, (tuple, list)) or not command:
            raise ContainerPolicyError("container command must be a non-empty argv sequence")
        normalized = []
        for argument in command:
            if not isinstance(argument, str) or "\x00" in argument:
                raise ContainerPolicyError("container command arguments must be safe strings")
            normalized.append(argument)
        return normalized

    @staticmethod
    def _mount_arg(source: Path, destination: str) -> str:
        return f"type=bind,src={source},dst={destination},readonly"

    @staticmethod
    def _is_within(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return path != root
        except ValueError:
            return False

def _valid_sha256(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdefABCDEF" for character in value)
    )


def directory_sha256(path_value: str | Path) -> str:
    """Hash a directory tree by relative path and file bytes, rejecting symlinks."""
    root = Path(path_value).resolve(strict=True)
    if not root.is_dir():
        raise ContainerPolicyError("digest source must be a directory")
    digest = hashlib.sha256()
    files = sorted((path for path in root.rglob("*") if path.is_file()), key=lambda p: p.as_posix())
    for path in files:
        if path.is_symlink():
            raise ContainerPolicyError("digest-pinned mount cannot contain symlinks")
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
    return digest.hexdigest()
