"""Deterministic PE/ELF metadata and mitigation inspection without code execution.

The parser reads headers only. Architecture, image type and mitigation flags are observations.
Strongly relevant missing/unsafe flags become *unverified hypotheses* and still require contextual
validation (for example, a library with no ASLR flag is not automatically a bounty finding).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class BinaryMetadataError(RuntimeError):
    pass


@dataclass(frozen=True)
class BinaryMetadataReport:
    file_name: str
    size_bytes: int
    sha256: str
    format: str
    architecture: str
    bits: int
    endianness: str
    image_type: str
    mitigations: dict[str, bool | None]
    details: dict[str, Any]
    candidates: tuple[dict, ...]


_PE_MACHINE = {
    0x014C: "x86",
    0x8664: "x86_64",
    0x01C0: "arm",
    0x01C4: "armv7",
    0xAA64: "aarch64",
}
_ELF_MACHINE = {
    3: "x86",
    8: "mips",
    20: "powerpc",
    21: "powerpc64",
    40: "arm",
    62: "x86_64",
    183: "aarch64",
    243: "riscv",
}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _candidate(*, weakness: str, summary: str, explanation: str, severity: str,
               file_name: str, kind: str) -> dict:
    return {
        "json_answer": {
            "vulnerability_type": weakness[:200],
            "file_path": file_name[:500],
            "line": 0,
            "summary": summary[:300],
            "explanation": explanation[:1600],
        },
        "severity": severity,
        "source": "aegis:binary-metadata",
        "confidence": 0.45,
        "validation_status": "unverified",
        "scanner_metadata": {
            "analysis_kind": kind,
            "context_required": True,
            "header_only": True,
        },
    }


def _parse_pe(data: bytes, file_name: str) -> tuple[str, int, str, str, dict, dict, tuple[dict, ...]]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise BinaryMetadataError("not a PE image")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset + 24 > len(data):
        raise BinaryMetadataError("PE header offset is outside the bounded header window")
    if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        raise BinaryMetadataError("invalid PE signature")
    machine, sections, _timestamp, _ptr, _symbols, optional_size, characteristics = struct.unpack_from(
        "<HHIIIHH", data, pe_offset + 4
    )
    optional = pe_offset + 24
    if optional + optional_size > len(data) or optional_size < 70:
        raise BinaryMetadataError("PE optional header is truncated")
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic == 0x10B:
        bits = 32
        dll_offset = optional + 70
    elif magic == 0x20B:
        bits = 64
        dll_offset = optional + 70
    else:
        raise BinaryMetadataError("unsupported PE optional-header magic")
    if dll_offset + 2 > len(data):
        raise BinaryMetadataError("PE DLL characteristics are truncated")
    dll = struct.unpack_from("<H", data, dll_offset)[0]
    is_dll = bool(characteristics & 0x2000)
    image_type = "dll" if is_dll else "executable"
    mitigations = {
        "high_entropy_va": bool(dll & 0x0020) if bits == 64 else None,
        "aslr_dynamic_base": bool(dll & 0x0040),
        "dep_nx_compat": bool(dll & 0x0100),
        "control_flow_guard": bool(dll & 0x4000),
    }
    candidates: list[dict] = []
    if not mitigations["dep_nx_compat"]:
        candidates.append(
            _candidate(
                weakness="PE image lacks NX compatibility flag",
                summary="PE header does not advertise NX compatibility",
                explanation=(
                    "The PE image lacks IMAGE_DLLCHARACTERISTICS_NX_COMPAT. Confirm the binary is an "
                    "in-scope production executable and whether platform policy still enforces DEP before impact claims."
                ),
                severity="low",
                file_name=file_name,
                kind="pe_nx_missing",
            )
        )
    if not mitigations["aslr_dynamic_base"]:
        candidates.append(
            _candidate(
                weakness="PE image lacks dynamic-base ASLR flag",
                summary="PE header does not advertise a dynamic base",
                explanation=(
                    "The image lacks IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE. Validate deployment/platform "
                    "mitigations and exploit relevance before treating this as security impact."
                ),
                severity="low",
                file_name=file_name,
                kind="pe_aslr_missing",
            )
        )
    details = {
        "machine_id": machine,
        "sections": sections,
        "characteristics": characteristics,
        "dll_characteristics": dll,
    }
    return _PE_MACHINE.get(machine, f"pe-machine-{machine}"), bits, "little", image_type, mitigations, details, tuple(candidates)


def _parse_elf(data: bytes, file_name: str) -> tuple[str, int, str, str, dict, dict, tuple[dict, ...]]:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise BinaryMetadataError("not an ELF image")
    elf_class = data[4]
    elf_data = data[5]
    if elf_class not in {1, 2} or elf_data not in {1, 2}:
        raise BinaryMetadataError("unsupported ELF class/endianness")
    bits = 32 if elf_class == 1 else 64
    endian = "little" if elf_data == 1 else "big"
    order = "<" if elf_data == 1 else ">"
    e_type, machine = struct.unpack_from(order + "HH", data, 16)
    image_type = {2: "executable", 3: "shared_or_pie", 1: "relocatable", 4: "core"}.get(
        e_type, f"elf-type-{e_type}"
    )
    if bits == 32:
        if len(data) < 52:
            raise BinaryMetadataError("ELF32 header is truncated")
        phoff = struct.unpack_from(order + "I", data, 28)[0]
        phentsize = struct.unpack_from(order + "H", data, 42)[0]
        phnum = struct.unpack_from(order + "H", data, 44)[0]
    else:
        phoff = struct.unpack_from(order + "Q", data, 32)[0]
        phentsize = struct.unpack_from(order + "H", data, 54)[0]
        phnum = struct.unpack_from(order + "H", data, 56)[0]
    executable_stack: bool | None = None
    gnu_relro = False
    for index in range(min(phnum, 4096)):
        offset = phoff + index * phentsize
        if phentsize <= 0 or offset + min(phentsize, 56) > len(data):
            break
        p_type = struct.unpack_from(order + "I", data, offset)[0]
        if bits == 32:
            p_flags = struct.unpack_from(order + "I", data, offset + 24)[0]
        else:
            p_flags = struct.unpack_from(order + "I", data, offset + 4)[0]
        if p_type == 0x6474E551:  # PT_GNU_STACK
            executable_stack = bool(p_flags & 0x1)
        elif p_type == 0x6474E552:  # PT_GNU_RELRO
            gnu_relro = True
    mitigations = {
        "pie_or_shared": e_type == 3,
        "gnu_relro_segment": gnu_relro,
        "non_executable_stack": None if executable_stack is None else not executable_stack,
    }
    candidates: list[dict] = []
    if executable_stack is True:
        candidates.append(
            _candidate(
                weakness="ELF executable stack",
                summary="ELF PT_GNU_STACK requests an executable stack",
                explanation=(
                    "The ELF program header marks the process stack executable. Confirm the binary is an "
                    "in-scope deployed executable and whether this materially enables an exploit chain."
                ),
                severity="medium",
                file_name=file_name,
                kind="elf_executable_stack",
            )
        )
    details = {
        "machine_id": machine,
        "elf_type": e_type,
        "program_header_count": phnum,
    }
    return _ELF_MACHINE.get(machine, f"elf-machine-{machine}"), bits, endian, image_type, mitigations, details, tuple(candidates)


def analyze_binary_metadata(
    binary_path: str | Path,
    *,
    max_header_bytes: int = 16 * 1024 * 1024,
    max_file_bytes: int = 8 * 1024 * 1024 * 1024,
) -> BinaryMetadataReport:
    path = Path(binary_path).expanduser().resolve()
    if not path.is_file():
        raise BinaryMetadataError("binary must be an existing regular file")
    size = path.stat().st_size
    if size <= 0 or size > max_file_bytes:
        raise BinaryMetadataError("binary size is outside the allowed range")
    with path.open("rb") as handle:
        data = handle.read(min(size, max_header_bytes))
    if data.startswith(b"MZ"):
        architecture, bits, endian, image_type, mitigations, details, candidates = _parse_pe(
            data, path.name
        )
        file_format = "pe"
    elif data.startswith(b"\x7fELF"):
        architecture, bits, endian, image_type, mitigations, details, candidates = _parse_elf(
            data, path.name
        )
        file_format = "elf"
    else:
        raise BinaryMetadataError("unsupported binary format")
    return BinaryMetadataReport(
        file_name=path.name,
        size_bytes=size,
        sha256=_sha256_file(path),
        format=file_format,
        architecture=architecture,
        bits=bits,
        endianness=endian,
        image_type=image_type,
        mitigations=mitigations,
        details=details,
        candidates=candidates,
    )
