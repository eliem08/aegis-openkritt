"""Non-deserializing model-format and provenance inspection.

This module never imports/loads a model with pickle, torch, keras, tensorflow, joblib, ONNX
runtime, or any framework deserializer. It reads bounded file/container metadata only:

* Safetensors: 8-byte little-endian JSON-header length + bounded header JSON;
* ZIP containers: entry names/sizes only, enough to recognize PyTorch ZIP checkpoints and
  ``.keras`` archives without reading ``data.pkl`` or weights;
* HDF5 / GGUF / pickle-protocol / extension-only hints as observations.

No format is itself a vulnerability. The output is provenance for ModelScan and later evidence.
"""

from __future__ import annotations

import hashlib
import json
import struct
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


class ModelProvenanceError(RuntimeError):
    pass


@dataclass(frozen=True)
class TensorHeader:
    name: str
    dtype: str
    shape: tuple[int, ...]
    data_start: int
    data_end: int


@dataclass(frozen=True)
class ModelProvenanceReport:
    file_name: str
    size_bytes: int
    sha256: str
    format: str
    format_confidence: str
    metadata_keys: tuple[str, ...]
    tensor_headers: tuple[TensorHeader, ...]
    archive_entries: int
    archive_uncompressed_bytes: int
    archive_names: tuple[str, ...]
    structural_flags: tuple[str, ...]
    deserialized: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "tensor_headers": [asdict(item) for item in self.tensor_headers],
        }


@dataclass(frozen=True)
class ModelArtifactTicket:
    ticket_id: str
    scope_digest: str
    sha256: str
    size_bytes: int
    file_name: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


_HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"
_PICKLE_EXTENSIONS = {".pkl", ".pickle", ".joblib"}
_PYTORCH_EXTENSIONS = {".pt", ".pth", ".ckpt", ".bin"}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_file(path: str | Path, *, max_file_bytes: int) -> Path:
    artifact = Path(path).expanduser().resolve()
    if not artifact.is_file():
        raise ModelProvenanceError("model artifact must be an existing regular file")
    size = artifact.stat().st_size
    if size <= 0 or size > max_file_bytes:
        raise ModelProvenanceError("model artifact size is outside the allowed range")
    return artifact


def _ticket_id(scope_digest: str, digest: str, size: int, file_name: str) -> str:
    payload = json.dumps(
        {
            "scope_digest": scope_digest,
            "sha256": digest,
            "size_bytes": size,
            "file_name": file_name,
            "purpose": "non-deserializing-model-inspection",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return "model-artifact:v1:" + hashlib.sha256(payload).hexdigest()


def issue_model_artifact_ticket(
    artifact_path: str | Path,
    *,
    scope_digest: str,
    max_file_bytes: int = 32 * 1024 * 1024 * 1024,
) -> ModelArtifactTicket:
    scope = str(scope_digest or "").strip()
    if not scope:
        raise ModelProvenanceError("scope_digest is required")
    artifact = _validate_file(artifact_path, max_file_bytes=max_file_bytes)
    size = artifact.stat().st_size
    digest = _sha256_file(artifact)
    return ModelArtifactTicket(
        ticket_id=_ticket_id(scope, digest, size, artifact.name),
        scope_digest=scope,
        sha256=digest,
        size_bytes=size,
        file_name=artifact.name,
    )


def verify_model_artifact_ticket(
    ticket: ModelArtifactTicket,
    artifact_path: str | Path,
    *,
    scope_digest: str,
    max_file_bytes: int = 32 * 1024 * 1024 * 1024,
) -> Path:
    scope = str(scope_digest or "").strip()
    if ticket.scope_digest != scope:
        raise ModelProvenanceError("model artifact ticket scope digest mismatch")
    artifact = _validate_file(artifact_path, max_file_bytes=max_file_bytes)
    size = artifact.stat().st_size
    digest = _sha256_file(artifact)
    expected = _ticket_id(scope, digest, size, artifact.name)
    if ticket.ticket_id != expected:
        raise ModelProvenanceError("model artifact changed after ticket issuance")
    if (ticket.sha256, ticket.size_bytes, ticket.file_name) != (digest, size, artifact.name):
        raise ModelProvenanceError("model artifact ticket metadata mismatch")
    return artifact


def _bounded_string(value: Any, limit: int = 160) -> str:
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return ""
    return str(value).replace("\x00", " ").replace("\r", " ").replace("\n", " ")[:limit]


def _safetensors(
    artifact: Path,
    *,
    max_header_bytes: int,
    max_tensors: int,
) -> tuple[tuple[str, ...], tuple[TensorHeader, ...]] | None:
    size = artifact.stat().st_size
    if size < 10:
        return None
    with artifact.open("rb") as handle:
        raw_len = handle.read(8)
        if len(raw_len) != 8:
            return None
        header_len = struct.unpack("<Q", raw_len)[0]
        if not 2 <= header_len <= max_header_bytes or 8 + header_len > size:
            return None
        header_raw = handle.read(header_len)
    # Safetensors JSON headers conventionally start with '{'. Refuse broad JSON guessing for
    # arbitrary binary formats that happen to have a small integer prefix.
    if not header_raw.lstrip().startswith(b"{"):
        return None
    try:
        header = json.loads(header_raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(header, dict):
        return None
    metadata_keys: tuple[str, ...] = ()
    metadata = header.get("__metadata__")
    if isinstance(metadata, dict):
        # Keys only. Values may contain user/model secrets and are intentionally not returned.
        metadata_keys = tuple(sorted(_bounded_string(key, 120) for key in metadata)[:500])

    tensor_rows: list[TensorHeader] = []
    data_bytes = size - 8 - header_len
    for name, value in header.items():
        if name == "__metadata__":
            continue
        if len(tensor_rows) >= max_tensors:
            raise ModelProvenanceError("Safetensors tensor count exceeds configured limit")
        if not isinstance(value, dict):
            raise ModelProvenanceError("Safetensors tensor header must be an object")
        dtype = _bounded_string(value.get("dtype"), 32)
        shape_raw = value.get("shape")
        offsets = value.get("data_offsets")
        if not isinstance(shape_raw, list) or not isinstance(offsets, list) or len(offsets) != 2:
            raise ModelProvenanceError("Safetensors tensor header is malformed")
        shape: list[int] = []
        for item in shape_raw[:64]:
            if not isinstance(item, int) or isinstance(item, bool) or item < 0:
                raise ModelProvenanceError("Safetensors tensor shape is invalid")
            shape.append(item)
        if len(shape_raw) > 64:
            raise ModelProvenanceError("Safetensors tensor rank exceeds configured limit")
        start, end = offsets
        if not isinstance(start, int) or not isinstance(end, int) or start < 0 or end < start:
            raise ModelProvenanceError("Safetensors data offsets are invalid")
        if end > data_bytes:
            raise ModelProvenanceError("Safetensors data offsets exceed artifact size")
        tensor_rows.append(
            TensorHeader(
                name=_bounded_string(name, 300),
                dtype=dtype,
                shape=tuple(shape),
                data_start=start,
                data_end=end,
            )
        )
    if not tensor_rows:
        return None
    return metadata_keys, tuple(tensor_rows)


def _zip_structure(
    artifact: Path,
    *,
    max_entries: int,
    max_uncompressed_bytes: int,
    max_compression_ratio: float,
    max_names: int,
) -> tuple[str, tuple[str, ...], int, int, tuple[str, ...]] | None:
    if not zipfile.is_zipfile(artifact):
        return None
    names: list[str] = []
    total_uncompressed = 0
    flags: set[str] = set()
    with zipfile.ZipFile(artifact) as bundle:
        infos = bundle.infolist()
        if len(infos) > max_entries:
            raise ModelProvenanceError("model archive exceeds entry-count limit")
        for info in infos:
            name = str(info.filename or "").replace("\\", "/")[:500]
            names.append(name)
            total_uncompressed += int(info.file_size)
            if total_uncompressed > max_uncompressed_bytes:
                raise ModelProvenanceError("model archive exceeds uncompressed-size limit")
            if info.file_size > 0:
                ratio = float(info.file_size) / max(1, int(info.compress_size))
                if ratio > max_compression_ratio:
                    raise ModelProvenanceError("model archive entry exceeds compression-ratio limit")
            if info.flag_bits & 0x1:
                flags.add("encrypted_archive_entry")

    lowered = {name.lower() for name in names}
    suffixes = {name.rsplit("/", 1)[-1].lower() for name in names}
    has_data_pkl = any(name.endswith("/data.pkl") or name == "data.pkl" for name in lowered)
    has_data_dir = any("/data/" in name or name.startswith("data/") for name in lowered)
    has_version = "version" in suffixes
    has_byteorder = "byteorder" in suffixes
    keras_root = {"config.json", "metadata.json", "model.weights.h5"}

    if keras_root.issubset(lowered):
        fmt = "keras_v3_zip"
        flags.add("keras_config_metadata_weights")
    elif has_data_pkl and (has_data_dir or has_version or has_byteorder):
        fmt = "pytorch_zip_checkpoint"
        flags.add("contains_pickle_metadata")
    else:
        fmt = "zip_archive"
    return (
        fmt,
        tuple(sorted(names)[:max_names]),
        len(names),
        total_uncompressed,
        tuple(sorted(flags)),
    )


def inspect_model_provenance(
    artifact_path: str | Path,
    *,
    ticket: ModelArtifactTicket,
    scope_digest: str,
    max_file_bytes: int = 32 * 1024 * 1024 * 1024,
    max_safetensors_header_bytes: int = 16 * 1024 * 1024,
    max_tensors: int = 100_000,
    max_archive_entries: int = 100_000,
    max_archive_uncompressed_bytes: int = 64 * 1024 * 1024 * 1024,
    max_compression_ratio: float = 500.0,
    max_archive_names: int = 2_000,
) -> ModelProvenanceReport:
    """Inspect format/provenance metadata only; never deserialize model payloads."""
    artifact = verify_model_artifact_ticket(
        ticket,
        artifact_path,
        scope_digest=scope_digest,
        max_file_bytes=max_file_bytes,
    )
    size = artifact.stat().st_size
    digest = ticket.sha256
    with artifact.open("rb") as handle:
        prefix = handle.read(32)

    safetensors = _safetensors(
        artifact,
        max_header_bytes=max_safetensors_header_bytes,
        max_tensors=max_tensors,
    )
    if safetensors is not None:
        metadata_keys, tensors = safetensors
        return ModelProvenanceReport(
            artifact.name,
            size,
            digest,
            "safetensors",
            "structural",
            metadata_keys,
            tensors,
            0,
            0,
            (),
            ("bounded_json_header_only",),
            False,
        )

    archive = _zip_structure(
        artifact,
        max_entries=max_archive_entries,
        max_uncompressed_bytes=max_archive_uncompressed_bytes,
        max_compression_ratio=max_compression_ratio,
        max_names=max_archive_names,
    )
    if archive is not None:
        fmt, names, count, uncompressed, flags = archive
        return ModelProvenanceReport(
            artifact.name,
            size,
            digest,
            fmt,
            "structural" if fmt != "zip_archive" else "container_only",
            (),
            (),
            count,
            uncompressed,
            names,
            flags,
            False,
        )

    extension = artifact.suffix.lower()
    if prefix.startswith(_HDF5_MAGIC):
        fmt, confidence, flags = "hdf5", "magic", ("container_not_opened",)
    elif prefix.startswith(b"GGUF"):
        fmt, confidence, flags = "gguf", "magic", ("header_magic_only",)
    elif len(prefix) >= 2 and prefix[0] == 0x80 and 0x02 <= prefix[1] <= 0x05:
        fmt, confidence, flags = "pickle_protocol", "magic", ("pickle_like_not_loaded",)
    elif extension in _PICKLE_EXTENSIONS:
        fmt, confidence, flags = "pickle_like", "extension", ("pickle_like_not_loaded",)
    elif extension in _PYTORCH_EXTENSIONS:
        fmt, confidence, flags = "pytorch_like", "extension", ("framework_extension_only",)
    elif extension == ".onnx":
        fmt, confidence, flags = "onnx_protobuf", "extension", ("protobuf_not_parsed",)
    else:
        fmt, confidence, flags = "unknown", "none", ()

    return ModelProvenanceReport(
        artifact.name,
        size,
        digest,
        fmt,
        confidence,
        (),
        (),
        0,
        0,
        (),
        tuple(flags),
        False,
    )
