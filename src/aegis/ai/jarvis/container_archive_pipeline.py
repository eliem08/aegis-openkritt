"""Safe local container-image archive pipeline.

Only an existing local uncompressed TAR archive is accepted. Aegis inspects Docker-save/OCI
manifest structure without extracting layers, then runs trusted Syft/Grype/Trivy scanners inside
the ticketed Bubblewrap networkless backend. Registry pulls, Kubernetes access, container starts,
and target-network traffic are outside this module.
"""

from __future__ import annotations

import hashlib
import json
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ..tool_runtime import ToolPin, ToolRuntimeManager
from .asset_deep_capabilities import DeepScannerMethod
from .asset_execution_ticket import AssetExecutionTicket, _ticket_id
from .asset_normalizers import AssetExecutionObservation, normalize_local_cli_execution
from .ticketed_networkless import execute_ticketed_networkless_method


class ContainerArchiveError(RuntimeError):
    pass


@dataclass(frozen=True)
class ContainerArchiveProvenance:
    file_name: str
    size_bytes: int
    sha256: str
    format: str
    member_count: int
    declared_bytes: int
    image_tags: tuple[str, ...]
    config_paths: tuple[str, ...]
    layer_paths: tuple[str, ...]
    manifest_digest_hints: tuple[str, ...]


@dataclass(frozen=True)
class ContainerStageResult:
    stage: str
    status: str
    detail: str = ""


@dataclass
class ContainerArchiveReport:
    archive_path: str
    scope_digest: str
    provenance: ContainerArchiveProvenance | None = None
    stages: list[ContainerStageResult] = field(default_factory=list)
    candidates: list[dict] = field(default_factory=list)
    observations: list[AssetExecutionObservation] = field(default_factory=list)
    engine_errors: dict[str, str] = field(default_factory=dict)


CONTAINER_SYFT_DOCKER = DeepScannerMethod(
    "syft",
    "docker-archive-sbom",
    ("syft", "docker-archive:{artifact}", "-o", "json"),
    local_only=True,
    output="json",
    purpose="inventory a local Docker image archive without pulling it",
)
CONTAINER_SYFT_OCI = DeepScannerMethod(
    "syft",
    "oci-archive-sbom",
    ("syft", "oci-archive:{artifact}", "-o", "json"),
    local_only=True,
    output="json",
    purpose="inventory a local OCI image archive without pulling it",
)
CONTAINER_GRYPE_DOCKER = DeepScannerMethod(
    "grype",
    "docker-archive-vulnerability-scan",
    ("grype", "docker-archive:{artifact}", "-o", "json"),
    local_only=True,
    output="json",
    purpose="scan a local Docker image archive against the worker's local vulnerability DB",
)
CONTAINER_GRYPE_OCI = DeepScannerMethod(
    "grype",
    "oci-archive-vulnerability-scan",
    ("grype", "oci-archive:{artifact}", "-o", "json"),
    local_only=True,
    output="json",
    purpose="scan a local OCI image archive against the worker's local vulnerability DB",
)
CONTAINER_TRIVY = DeepScannerMethod(
    "trivy",
    "image-archive-vulnerability-scan",
    ("trivy", "image", "--input", "{artifact}", "--format", "json"),
    local_only=True,
    output="json",
    purpose="scan a local image archive with the worker's local Trivy databases",
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_archive(path: str | Path, *, max_file_bytes: int) -> Path:
    archive = Path(path).expanduser().resolve()
    if not archive.is_file():
        raise ContainerArchiveError("container archive must be an existing regular file")
    size = archive.stat().st_size
    if size <= 0 or size > max_file_bytes:
        raise ContainerArchiveError("container archive size is outside the allowed range")
    return archive


def _read_json_member(bundle: tarfile.TarFile, member: tarfile.TarInfo, *, limit: int) -> Any:
    if member.size < 0 or member.size > limit:
        raise ContainerArchiveError(f"container metadata member is oversized: {member.name}")
    handle = bundle.extractfile(member)
    if handle is None:
        raise ContainerArchiveError(f"container metadata member cannot be read: {member.name}")
    with handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ContainerArchiveError(f"container metadata member exceeded bound: {member.name}")
    try:
        return json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContainerArchiveError(f"invalid JSON metadata: {member.name}") from exc


def inspect_container_archive(
    archive_path: str | Path,
    *,
    max_file_bytes: int = 64 * 1024 * 1024 * 1024,
    max_members: int = 200_000,
    max_declared_bytes: int = 256 * 1024 * 1024 * 1024,
    max_metadata_bytes: int = 32 * 1024 * 1024,
    max_layers: int = 20_000,
) -> ContainerArchiveProvenance:
    """Inspect TAR member metadata and selected manifest JSON without extracting image layers."""
    archive = _validate_archive(archive_path, max_file_bytes=max_file_bytes)
    try:
        bundle = tarfile.open(archive, mode="r:")
    except tarfile.TarError as exc:
        raise ContainerArchiveError(
            "container archive must be an uncompressed TAR; compressed streams need a separate backend"
        ) from exc

    tags: set[str] = set()
    configs: set[str] = set()
    layers: set[str] = set()
    digest_hints: set[str] = set()
    declared = 0
    with bundle:
        members = bundle.getmembers()
        if len(members) > max_members:
            raise ContainerArchiveError("container archive exceeds member-count limit")
        by_name = {member.name.replace("\\", "/"): member for member in members}
        for member in members:
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise ContainerArchiveError("container archive links/devices/FIFOs are not allowed")
            if member.size < 0:
                raise ContainerArchiveError("container archive member has an invalid size")
            declared += int(member.size)
            if declared > max_declared_bytes:
                raise ContainerArchiveError("container archive exceeds declared-byte limit")

        docker_manifest = by_name.get("manifest.json")
        oci_layout = by_name.get("oci-layout")
        oci_index = by_name.get("index.json")
        if docker_manifest is not None:
            payload = _read_json_member(bundle, docker_manifest, limit=max_metadata_bytes)
            if not isinstance(payload, list):
                raise ContainerArchiveError("Docker manifest.json must be a list")
            for image in payload[:5000]:
                if not isinstance(image, dict):
                    continue
                config = image.get("Config")
                if isinstance(config, str) and config:
                    configs.add(config[:500])
                repo_tags = image.get("RepoTags")
                if isinstance(repo_tags, list):
                    for tag in repo_tags[:500]:
                        if isinstance(tag, str) and tag:
                            tags.add(tag[:500])
                raw_layers = image.get("Layers")
                if isinstance(raw_layers, list):
                    for layer in raw_layers:
                        if len(layers) >= max_layers:
                            raise ContainerArchiveError("Docker archive exceeds layer-count limit")
                        if isinstance(layer, str) and layer:
                            layers.add(layer[:500])
            fmt = "docker_save_tar"
        elif oci_layout is not None and oci_index is not None:
            payload = _read_json_member(bundle, oci_index, limit=max_metadata_bytes)
            if not isinstance(payload, dict):
                raise ContainerArchiveError("OCI index.json must be an object")
            manifests = payload.get("manifests")
            if isinstance(manifests, list):
                for item in manifests[:10000]:
                    if not isinstance(item, dict):
                        continue
                    digest = item.get("digest")
                    if isinstance(digest, str) and digest:
                        digest_hints.add(digest[:200])
                    annotations = item.get("annotations")
                    if isinstance(annotations, dict):
                        for key, value in annotations.items():
                            if str(key).endswith("ref.name") and isinstance(value, str):
                                tags.add(value[:500])
            fmt = "oci_image_layout_tar"
        else:
            raise ContainerArchiveError("archive is neither Docker-save nor OCI image layout")

    return ContainerArchiveProvenance(
        file_name=archive.name,
        size_bytes=archive.stat().st_size,
        sha256=_sha256_file(archive),
        format=fmt,
        member_count=len(members),
        declared_bytes=declared,
        image_tags=tuple(sorted(tags)),
        config_paths=tuple(sorted(configs)),
        layer_paths=tuple(sorted(layers)),
        manifest_digest_hints=tuple(sorted(digest_hints)),
    )


def _ticket(provenance: ContainerArchiveProvenance, method: DeepScannerMethod,
            *, scope_digest: str) -> AssetExecutionTicket:
    scope = str(scope_digest or "").strip()
    if not scope:
        raise ContainerArchiveError("scope_digest is required")
    requirements = (
        "authorized_local_container_archive",
        f"archive_sha256:{provenance.sha256}",
        "no_registry_pull",
    )
    material = {
        "scope_digest": scope,
        "asset_kind": "container_image_archive",
        "tool": method.tool,
        "method": method.method,
        "requirements": requirements,
        "availability_digest": provenance.sha256,
        "offline_only": True,
    }
    return AssetExecutionTicket(
        ticket_id=_ticket_id(material),
        scope_digest=scope,
        asset_kind="container_image_archive",
        tool=method.tool,
        method=method.method,
        requirements=requirements,
        availability_digest=provenance.sha256,
        offline_only=True,
    )


def _methods(provenance: ContainerArchiveProvenance) -> tuple[DeepScannerMethod, ...]:
    if provenance.format == "docker_save_tar":
        return (CONTAINER_SYFT_DOCKER, CONTAINER_GRYPE_DOCKER, CONTAINER_TRIVY)
    return (CONTAINER_SYFT_OCI, CONTAINER_GRYPE_OCI, CONTAINER_TRIVY)


def _dedupe(rows: Iterable[dict]) -> list[dict]:
    output: list[dict] = []
    seen: set[tuple[str, str, int, str]] = set()
    for row in rows:
        answer = row.get("json_answer") or {}
        key = (
            str(answer.get("vulnerability_type") or row.get("cwe") or ""),
            str(answer.get("file_path") or ""),
            int(answer.get("line") or 0),
            str(answer.get("summary") or ""),
        )
        if key not in seen:
            seen.add(key)
            output.append(row)
    return output


def run_container_archive_pipeline(
    archive_path: str | Path,
    *,
    scope_digest: str,
    workspace_root: str | Path | None = None,
    runtime_manager: ToolRuntimeManager | None = None,
    pins: dict[str, ToolPin] | None = None,
    process_runner=None,
) -> ContainerArchiveReport:
    """Inspect and scan one local image archive; preserve partial scanner failures."""
    archive = Path(archive_path).expanduser().resolve()
    report = ContainerArchiveReport(str(archive), str(scope_digest))
    try:
        provenance = inspect_container_archive(archive)
        report.provenance = provenance
        report.observations.append(
            AssetExecutionObservation(
                kind="container_archive_metadata",
                tool="aegis-container-archive",
                method="non-extracting-manifest-inspection",
                data={
                    "file_name": provenance.file_name,
                    "size_bytes": provenance.size_bytes,
                    "sha256": provenance.sha256,
                    "format": provenance.format,
                    "member_count": provenance.member_count,
                    "declared_bytes": provenance.declared_bytes,
                    "image_tags": provenance.image_tags,
                    "config_paths": provenance.config_paths,
                    "layer_paths": provenance.layer_paths,
                    "manifest_digest_hints": provenance.manifest_digest_hints,
                    "layers_extracted": False,
                    "verification_state": "observation",
                },
            )
        )
        report.stages.append(ContainerStageResult("metadata", "complete"))
    except Exception as exc:
        report.engine_errors["metadata"] = f"{type(exc).__name__}: {exc}"[:240]
        report.stages.append(ContainerStageResult("metadata", "failed", report.engine_errors["metadata"]))
        return report

    rows: list[dict] = []
    for method in _methods(provenance):
        identity = f"{method.tool}/{method.method}"
        try:
            if _sha256_file(archive) != provenance.sha256:
                raise ContainerArchiveError("container archive changed during the analysis run")
            ticket = _ticket(provenance, method, scope_digest=scope_digest)
            execution = execute_ticketed_networkless_method(
                method,
                ticket=ticket,
                scope_digest=scope_digest,
                artifact_path=archive,
                workspace_root=workspace_root,
                runtime_manager=runtime_manager,
                pins=pins,
                process_runner=process_runner,
            )
            if _sha256_file(archive) != provenance.sha256:
                raise ContainerArchiveError("container archive changed after scanner execution")
            normalized = normalize_local_cli_execution(execution)
            for candidate in normalized.candidates:
                candidate.setdefault("container_archive", {}).update(
                    {"sha256": provenance.sha256, "format": provenance.format}
                )
            rows.extend(normalized.candidates)
            report.observations.extend(normalized.observations)
            report.stages.append(ContainerStageResult(identity, "complete"))
        except Exception as exc:
            report.engine_errors[identity] = f"{type(exc).__name__}: {exc}"[:240]
            report.stages.append(ContainerStageResult(identity, "failed", report.engine_errors[identity]))
    report.candidates = _dedupe(rows)
    return report
