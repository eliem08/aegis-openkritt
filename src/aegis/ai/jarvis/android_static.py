"""Networkless Android static decompilation for authorized APK artifacts.

This path is intentionally static. It does not acquire APKs from stores, start emulators, attach
Frida, bypass device protections, or contact a target. An existing APK is SHA-256 bound to one
explicit JADX/apktool ticket and decompiled inside the Bubblewrap networkless scanner boundary.
The derived tree is integrity-hashed and rejected if it contains symlinks.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from ..tool_runtime import ToolPin, ToolRuntimeManager
from .asset_deep_capabilities import DeepScannerMethod
from .asset_execution_ticket import (
    AssetExecutionTicket,
    AssetExecutionTicketError,
    _ticket_id,
    verify_offline_execution_ticket,
)
from .networkless_cli import execute_networkless_cli_method

ANDROID_JADX = DeepScannerMethod(
    "jadx",
    "android-decompile",
    ("jadx", "-d", "{output_dir}", "{artifact}"),
    local_only=True,
    output="directory",
    purpose="decompile an authorized APK into Java-like sources and resources",
)
ANDROID_APKTOOL = DeepScannerMethod(
    "apktool",
    "android-resource-decode",
    ("apktool", "d", "-f", "{artifact}", "-o", "{output_dir}"),
    local_only=True,
    output="directory",
    purpose="decode an authorized APK manifest/resources and smali without execution",
)
ANDROID_STATIC_METHODS = (ANDROID_JADX, ANDROID_APKTOOL)


class AndroidStaticError(RuntimeError):
    pass


@dataclass(frozen=True)
class AndroidDerivedTree:
    tool: str
    method: str
    apk_sha256: str
    root: str
    tree_digest: str
    file_count: int
    total_bytes: int
    runtime_provenance: dict


@dataclass(frozen=True)
class AndroidStaticOutcome:
    candidates: tuple[dict, ...]
    observation: dict
    derived_tree: AndroidDerivedTree


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_apk(path: str | Path, *, max_bytes: int = 2 * 1024 * 1024 * 1024) -> Path:
    apk = Path(path).expanduser().resolve()
    if not apk.is_file():
        raise AndroidStaticError("APK must be an existing regular file")
    if apk.suffix.lower() != ".apk":
        raise AndroidStaticError("static Android decompilation accepts .apk artifacts only")
    size = apk.stat().st_size
    if size <= 0 or size > max_bytes:
        raise AndroidStaticError("APK size is outside the allowed range")
    return apk


def _supported(method: DeepScannerMethod) -> bool:
    identity = (str(method.tool), str(method.method))
    return any((str(item.tool), str(item.method)) == identity for item in ANDROID_STATIC_METHODS)


def _tree_digest(root: Path, *, max_files: int = 100_000,
                 max_total_bytes: int = 4 * 1024 * 1024 * 1024) -> tuple[str, int, int]:
    rows: list[tuple[str, int, str]] = []
    total = 0
    count = 0
    if not root.is_dir():
        raise AndroidStaticError("decompiler did not produce an output directory")
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise AndroidStaticError("derived Android tree contains a symlink")
        if not path.is_file():
            continue
        count += 1
        if count > max_files:
            raise AndroidStaticError("derived Android tree exceeds file-count limit")
        size = path.stat().st_size
        total += size
        if total > max_total_bytes:
            raise AndroidStaticError("derived Android tree exceeds byte limit")
        rows.append((path.relative_to(root).as_posix(), size, _sha256_file(path)))
    encoded = json.dumps(rows, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest(), count, total


def issue_android_static_ticket(
    apk_path: str | Path,
    method: DeepScannerMethod,
    *,
    scope_digest: str,
) -> AssetExecutionTicket:
    """Bind one explicit static decompiler to the exact authorized APK digest."""
    if not _supported(method):
        raise AssetExecutionTicketError("method is not a registered Android static decompiler")
    scope = str(scope_digest or "").strip()
    if not scope:
        raise AssetExecutionTicketError("scope_digest is required")
    apk = _validate_apk(apk_path)
    digest = _sha256_file(apk)
    requirements = ("authorized_artifact", f"apk_sha256:{digest}")
    material = {
        "scope_digest": scope,
        "asset_kind": "android_apk",
        "tool": str(method.tool),
        "method": str(method.method),
        "requirements": requirements,
        "availability_digest": digest,
        "offline_only": True,
    }
    return AssetExecutionTicket(
        ticket_id=_ticket_id(material),
        scope_digest=scope,
        asset_kind="android_apk",
        tool=str(method.tool),
        method=str(method.method),
        requirements=requirements,
        availability_digest=digest,
        offline_only=True,
    )


def execute_android_static(
    apk_path: str | Path,
    method: DeepScannerMethod,
    *,
    ticket: AssetExecutionTicket,
    scope_digest: str,
    workspace_root: str | Path | None = None,
    runtime_manager: ToolRuntimeManager | None = None,
    pins: dict[str, ToolPin] | None = None,
    process_runner=None,
) -> AndroidStaticOutcome:
    """Run one static decompiler networklessly and return an integrity-bound derived tree."""
    if not _supported(method):
        raise AndroidStaticError("method is not a registered Android static decompiler")
    try:
        verify_offline_execution_ticket(ticket, method, scope_digest=scope_digest)
    except AssetExecutionTicketError as exc:
        raise AndroidStaticError(str(exc)) from exc
    if ticket.asset_kind != "android_apk":
        raise AndroidStaticError("ticket does not authorize an Android APK")
    apk = _validate_apk(apk_path)
    digest = _sha256_file(apk)
    if digest != ticket.availability_digest:
        raise AndroidStaticError("APK digest changed after ticket issuance")

    execution = execute_networkless_cli_method(
        method,
        artifact_path=apk,
        workspace_root=workspace_root,
        retain_workspace=True,
        runtime_manager=runtime_manager,
        pins=pins,
        process_runner=process_runner,
    )
    if execution.returncode != 0 or execution.timed_out:
        if execution.workspace:
            shutil.rmtree(execution.workspace, ignore_errors=True)
        raise AndroidStaticError(
            f"{method.tool} decompilation failed with return code {execution.returncode}"
        )
    root = Path(execution.workspace) / "output"
    try:
        tree_digest, file_count, total_bytes = _tree_digest(root)
    except Exception:
        if execution.workspace:
            shutil.rmtree(execution.workspace, ignore_errors=True)
        raise
    derived = AndroidDerivedTree(
        tool=str(method.tool),
        method=str(method.method),
        apk_sha256=digest,
        root=str(root),
        tree_digest=tree_digest,
        file_count=file_count,
        total_bytes=total_bytes,
        runtime_provenance=execution.provenance,
    )
    observation = {
        "kind": "android_derived_source",
        "tool": derived.tool,
        "method": derived.method,
        "apk_sha256": derived.apk_sha256,
        "tree_digest": derived.tree_digest,
        "file_count": derived.file_count,
        "total_bytes": derived.total_bytes,
        "network_enforcement": execution.provenance.get("network_enforcement"),
        "verification_state": "observation",
    }
    return AndroidStaticOutcome(candidates=(), observation=observation, derived_tree=derived)


def cleanup_android_static(tree: AndroidDerivedTree) -> None:
    root = Path(tree.root).resolve()
    workspace = root.parent
    if workspace.name.startswith("aegis-asset-"):
        shutil.rmtree(workspace, ignore_errors=True)


__all__ = [
    "ANDROID_APKTOOL",
    "ANDROID_JADX",
    "ANDROID_STATIC_METHODS",
    "AndroidDerivedTree",
    "AndroidStaticError",
    "AndroidStaticOutcome",
    "cleanup_android_static",
    "execute_android_static",
    "issue_android_static_ticket",
]
