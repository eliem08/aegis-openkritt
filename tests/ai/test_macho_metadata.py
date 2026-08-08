from __future__ import annotations

import struct

import pytest

from aegis.ai.jarvis.macho_metadata import MachOError, analyze_macho_metadata


def _align(value: bytes, multiple: int = 8) -> bytes:
    pad = (-len(value)) % multiple
    return value + b"\x00" * pad


def _thin_arm64() -> bytes:
    commands = []

    dylib_name = b"/usr/lib/libSystem.B.dylib\x00"
    dylib_cmdsize = len(_align(b"\x00" * 24 + dylib_name))
    dylib = bytearray(dylib_cmdsize)
    struct.pack_into("<II", dylib, 0, 0x0C, dylib_cmdsize)
    struct.pack_into("<I", dylib, 8, 24)
    dylib[24:24 + len(dylib_name)] = dylib_name
    commands.append(bytes(dylib))

    rpath_name = b"@executable_path/Frameworks\x00"
    rpath_cmdsize = len(_align(b"\x00" * 12 + rpath_name))
    rpath = bytearray(rpath_cmdsize)
    struct.pack_into("<II", rpath, 0, 0x8000001C, rpath_cmdsize)
    struct.pack_into("<I", rpath, 8, 12)
    rpath[12:12 + len(rpath_name)] = rpath_name
    commands.append(bytes(rpath))

    code_sig = bytearray(16)
    struct.pack_into("<IIII", code_sig, 0, 0x1D, 16, 0x200, 64)
    commands.append(bytes(code_sig))

    encryption = bytearray(24)
    struct.pack_into("<IIIIII", encryption, 0, 0x2C, 24, 0x1000, 0x2000, 1, 0)
    commands.append(bytes(encryption))

    sizeofcmds = sum(len(item) for item in commands)
    header = bytearray(32)
    header[:4] = b"\xcf\xfa\xed\xfe"
    struct.pack_into(
        "<IIIIII",
        header,
        4,
        0x0100000C,  # arm64
        0,
        2,  # MH_EXECUTE
        len(commands),
        sizeofcmds,
        0x00200000,  # MH_PIE
    )
    struct.pack_into("<I", header, 28, 0)
    return bytes(header) + b"".join(commands) + b"\x00" * 256


def _fat() -> bytes:
    data = bytearray(8 + 2 * 20 + 64)
    struct.pack_into(">II", data, 0, 0xCAFEBABE, 2)
    # x86_64 slice metadata
    struct.pack_into(">IIIII", data, 8, 0x01000007, 3, 0x1000, 0x2000, 12)
    # arm64 slice metadata
    struct.pack_into(">IIIII", data, 28, 0x0100000C, 0, 0x4000, 0x3000, 12)
    return bytes(data)


def test_thin_arm64_macho_parses_pie_signature_encryption_dylib_and_rpath(tmp_path):
    binary = tmp_path / "DemoExec"
    binary.write_bytes(_thin_arm64())
    report = analyze_macho_metadata(binary)
    assert report.format == "macho"
    assert report.architectures == ("arm64",)
    assert report.bits == 64
    assert report.endianness == "little"
    assert report.file_type == "executable"
    assert report.pie is True
    assert report.code_signature is True
    assert report.encryption_info is True
    assert report.encrypted is True
    assert report.dylibs == ("/usr/lib/libSystem.B.dylib",)
    assert report.rpaths == ("@executable_path/Frameworks",)
    assert report.load_command_count == 4
    assert len(report.sha256) == 64


def test_fat_macho_reports_architectures_without_guessing_slice_metadata(tmp_path):
    binary = tmp_path / "Universal"
    binary.write_bytes(_fat())
    report = analyze_macho_metadata(binary)
    assert report.format == "fat_macho"
    assert report.architectures == ("arm64", "x86_64")
    assert report.bits is None
    assert report.file_type == "multiple"
    assert report.pie is None
    assert report.code_signature is None
    assert report.encryption_info is None


def test_invalid_load_command_size_fails_closed(tmp_path):
    data = bytearray(64)
    data[:4] = b"\xcf\xfa\xed\xfe"
    struct.pack_into("<IIIIII", data, 4, 0x0100000C, 0, 2, 1, 8, 0)
    struct.pack_into("<I", data, 28, 0)
    struct.pack_into("<II", data, 32, 0x0C, 4)  # cmdsize must be >= 8
    binary = tmp_path / "bad"
    binary.write_bytes(data)
    with pytest.raises(MachOError, match="load command size"):
        analyze_macho_metadata(binary)


def test_truncated_and_non_macho_inputs_fail_closed(tmp_path):
    truncated = tmp_path / "short"
    truncated.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 8)
    with pytest.raises(MachOError, match="header is truncated"):
        analyze_macho_metadata(truncated)

    unknown = tmp_path / "unknown"
    unknown.write_bytes(b"not-macho")
    with pytest.raises(MachOError, match="unsupported Mach-O magic"):
        analyze_macho_metadata(unknown)
