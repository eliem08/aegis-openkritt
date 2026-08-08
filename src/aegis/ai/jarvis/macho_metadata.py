"""Deterministic Mach-O metadata parsing without execution or platform tooling."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path


class MachOError(RuntimeError):
    pass


@dataclass(frozen=True)
class MachOMetadata:
    file_name: str
    size_bytes: int
    sha256: str
    format: str
    architectures: tuple[str, ...]
    bits: int | None
    endianness: str
    file_type: str
    pie: bool | None
    code_signature: bool | None
    encryption_info: bool | None
    encrypted: bool | None
    dylibs: tuple[str, ...]
    rpaths: tuple[str, ...]
    load_command_count: int


_CPU = {
    7: "x86",
    0x01000007: "x86_64",
    12: "arm",
    0x0100000C: "arm64",
    0x0200000C: "arm64_32",
}
_FILE_TYPE = {
    1: "object",
    2: "executable",
    3: "fixed_vm_library",
    4: "core",
    5: "preload",
    6: "dylib",
    7: "dylinker",
    8: "bundle",
    9: "dylib_stub",
}
_MH_PIE = 0x00200000
_LC_LOAD_DYLIB = 0x0C
_LC_LOAD_WEAK_DYLIB = 0x80000018
_LC_REEXPORT_DYLIB = 0x8000001F
_LC_LOAD_UPWARD_DYLIB = 0x80000023
_LC_RPATH = 0x8000001C
_LC_CODE_SIGNATURE = 0x1D
_LC_ENCRYPTION_INFO = 0x21
_LC_ENCRYPTION_INFO_64 = 0x2C


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _bounded_cstring(data: bytes, start: int, end: int, limit: int = 500) -> str:
    if not 0 <= start < end <= len(data):
        return ""
    raw = data[start:min(end, start + limit)]
    raw = raw.split(b"\x00", 1)[0]
    return raw.decode("utf-8", errors="replace").replace("\r", " ").replace("\n", " ")[:limit]


def _fat_architectures(data: bytes, *, magic: int) -> tuple[str, ...]:
    is_64 = magic in {0xCAFEBABF, 0xBFBAFECA}
    endian = ">" if magic in {0xCAFEBABE, 0xCAFEBABF} else "<"
    if len(data) < 8:
        raise MachOError("fat Mach-O header is truncated")
    count = struct.unpack_from(endian + "I", data, 4)[0]
    if count > 128:
        raise MachOError("fat Mach-O architecture count exceeds limit")
    stride = 32 if is_64 else 20
    architectures: set[str] = set()
    for index in range(count):
        offset = 8 + index * stride
        if offset + stride > len(data):
            raise MachOError("fat Mach-O architecture table is truncated")
        cputype = struct.unpack_from(endian + "I", data, offset)[0]
        architectures.add(_CPU.get(cputype, f"cpu-{cputype}"))
    return tuple(sorted(architectures))


def analyze_macho_metadata(
    binary_path: str | Path,
    *,
    max_header_bytes: int = 64 * 1024 * 1024,
    max_file_bytes: int = 8 * 1024 * 1024 * 1024,
) -> MachOMetadata:
    path = Path(binary_path).expanduser().resolve()
    if not path.is_file():
        raise MachOError("Mach-O input must be an existing regular file")
    size = path.stat().st_size
    if size <= 0 or size > max_file_bytes:
        raise MachOError("Mach-O size is outside the allowed range")
    with path.open("rb") as handle:
        data = handle.read(min(size, max_header_bytes))
    if len(data) < 4:
        raise MachOError("Mach-O header is truncated")
    magic_be = struct.unpack_from(">I", data, 0)[0]
    if magic_be in {0xCAFEBABE, 0xCAFEBABF, 0xBEBAFECA, 0xBFBAFECA}:
        return MachOMetadata(
            file_name=path.name,
            size_bytes=size,
            sha256=_sha256_file(path),
            format="fat_macho",
            architectures=_fat_architectures(data, magic=magic_be),
            bits=None,
            endianness="big" if magic_be in {0xCAFEBABE, 0xCAFEBABF} else "little",
            file_type="multiple",
            pie=None,
            code_signature=None,
            encryption_info=None,
            encrypted=None,
            dylibs=(),
            rpaths=(),
            load_command_count=0,
        )

    raw_magic = data[:4]
    thin = {
        b"\xce\xfa\xed\xfe": (32, "little", "<"),
        b"\xfe\xed\xfa\xce": (32, "big", ">"),
        b"\xcf\xfa\xed\xfe": (64, "little", "<"),
        b"\xfe\xed\xfa\xcf": (64, "big", ">"),
    }.get(raw_magic)
    if thin is None:
        raise MachOError("unsupported Mach-O magic")
    bits, endianness, order = thin
    header_size = 32 if bits == 64 else 28
    if len(data) < header_size:
        raise MachOError("Mach-O header is truncated")
    cputype, _cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
        order + "IIIIII", data, 4
    )
    if ncmds > 100_000 or sizeofcmds > max_header_bytes:
        raise MachOError("Mach-O load-command metadata exceeds limit")
    command_end = header_size + sizeofcmds
    if command_end > len(data):
        raise MachOError("Mach-O load commands are outside the bounded header window")

    dylibs: set[str] = set()
    rpaths: set[str] = set()
    code_signature = False
    encryption_info = False
    encrypted: bool | None = None
    cursor = header_size
    dylib_commands = {
        _LC_LOAD_DYLIB,
        _LC_LOAD_WEAK_DYLIB,
        _LC_REEXPORT_DYLIB,
        _LC_LOAD_UPWARD_DYLIB,
    }
    for _index in range(ncmds):
        if cursor + 8 > command_end:
            raise MachOError("Mach-O load command is truncated")
        cmd, cmdsize = struct.unpack_from(order + "II", data, cursor)
        if cmdsize < 8 or cursor + cmdsize > command_end:
            raise MachOError("Mach-O load command size is invalid")
        if cmd in dylib_commands and cmdsize >= 24:
            name_offset = struct.unpack_from(order + "I", data, cursor + 8)[0]
            name = _bounded_cstring(data, cursor + name_offset, cursor + cmdsize)
            if name:
                dylibs.add(name)
        elif cmd == _LC_RPATH and cmdsize >= 12:
            path_offset = struct.unpack_from(order + "I", data, cursor + 8)[0]
            value = _bounded_cstring(data, cursor + path_offset, cursor + cmdsize)
            if value:
                rpaths.add(value)
        elif cmd == _LC_CODE_SIGNATURE:
            code_signature = True
        elif cmd in {_LC_ENCRYPTION_INFO, _LC_ENCRYPTION_INFO_64} and cmdsize >= 20:
            encryption_info = True
            cryptid = struct.unpack_from(order + "I", data, cursor + 16)[0]
            encrypted = bool(cryptid)
        cursor += cmdsize

    return MachOMetadata(
        file_name=path.name,
        size_bytes=size,
        sha256=_sha256_file(path),
        format="macho",
        architectures=(_CPU.get(cputype, f"cpu-{cputype}"),),
        bits=bits,
        endianness=endianness,
        file_type=_FILE_TYPE.get(filetype, f"type-{filetype}"),
        pie=bool(flags & _MH_PIE),
        code_signature=code_signature,
        encryption_info=encryption_info,
        encrypted=encrypted,
        dylibs=tuple(sorted(dylibs)),
        rpaths=tuple(sorted(rpaths)),
        load_command_count=ncmds,
    )
