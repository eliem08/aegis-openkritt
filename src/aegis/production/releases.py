"""Runtime validation for approved scanner and browser releases."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from aegis.supply import verify_image_pin
from aegis.tools.pin import PinnedTool


class ReleaseLockError(RuntimeError):
    pass


@dataclass(frozen=True)
class LockedRelease:
    name: str
    version: str
    sha256: str
    image: str
    license_reviewed: bool
    output_schema: str
    executable_path: str = ""
    source: str = ""
    signed_by: str = ""

    def validate(self, *, require_executable: bool = False) -> None:
        if not self.name or not self.version or not self.output_schema:
            raise ReleaseLockError("release identity and output schema are required")
        if len(self.sha256) != 64 or any(c not in "0123456789abcdefABCDEF" for c in self.sha256):
            raise ReleaseLockError(f"{self.name}: invalid sha256")
        verify_image_pin(self.image)
        if not self.license_reviewed:
            raise ReleaseLockError(f"{self.name}: license review is not approved")
        if require_executable and not self.executable_path:
            raise ReleaseLockError(f"{self.name}: executable path is required")

    def verify_executable(self) -> None:
        self.validate(require_executable=True)
        path = Path(self.executable_path)
        if not path.is_file():
            raise ReleaseLockError(f"{self.name}: executable is missing")
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        if digest.hexdigest().lower() != self.sha256.lower():
            raise ReleaseLockError(f"{self.name}: executable checksum mismatch")

    def as_pinned_tool(self) -> PinnedTool:
        return PinnedTool(
            tool=self.name, version=self.version, sha256=self.sha256,
            source=self.source, signed_by=self.signed_by,
        )


def load_release_lock(path_text: str, *, require_executables: bool = False) -> dict[str, LockedRelease]:
    path = Path(path_text)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseLockError("release lock is missing or invalid") from exc
    if not isinstance(document, dict) or document.get("schema") != 1:
        raise ReleaseLockError("unsupported release lock schema")
    raw_releases = document.get("releases")
    if not isinstance(raw_releases, list) or not raw_releases:
        raise ReleaseLockError("release lock contains no approved releases")
    releases: dict[str, LockedRelease] = {}
    for raw in raw_releases:
        try:
            release = LockedRelease(**raw)
        except TypeError as exc:
            raise ReleaseLockError("release lock entry has unknown or missing fields") from exc
        release.validate(require_executable=require_executables)
        if release.name in releases:
            raise ReleaseLockError(f"duplicate release: {release.name}")
        releases[release.name] = release
    return releases


def verify_locked_executables(path_text: str) -> dict[str, PinnedTool]:
    releases = load_release_lock(path_text, require_executables=True)
    for release in releases.values():
        release.verify_executable()
    return {name: release.as_pinned_tool() for name, release in releases.items()}
