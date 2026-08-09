from __future__ import annotations

import struct

import pytest

from aegis.ai.jarvis.binary_metadata import BinaryMetadataError, analyze_binary_metadata


def _pe64(*, dll_characteristics: int, machine: int = 0x8664, is_dll: bool = False) -> bytes:
    data = bytearray(0x300)
    data[:2] = b"MZ"
    pe = 0x80
    struct.pack_into("<I", data, 0x3C, pe)
    data[pe:pe + 4] = b"PE\x00\x00"
    characteristics = 0x0002 | (0x2000 if is_dll else 0)
    # IMAGE_FILE_HEADER: Machine, NumberOfSections, TimeDateStamp, PointerToSymbolTable,
    # NumberOfSymbols, SizeOfOptionalHeader, Characteristics.
    struct.pack_into("<HHIIIHH", data, pe + 4, machine, 3, 0, 0, 0, 0xF0, characteristics)
    optional = pe + 24
    struct.pack_into("<H", data, optional, 0x20B)  # PE32+
    struct.pack_into("<H", data, optional + 70, dll_characteristics)
    return bytes(data)


def _elf64(*, stack_executable: bool, relro: bool = True, machine: int = 62,
           elf_type: int = 3) -> bytes:
    phnum = 2 if relro else 1
    phentsize = 56
    phoff = 64
    data = bytearray(phoff + phnum * phentsize + 64)
    data[:4] = b"\x7fELF"
    data[4] = 2  # ELFCLASS64
    data[5] = 1  # little endian
    data[6] = 1
    struct.pack_into("<HHI", data, 16, elf_type, machine, 1)
    struct.pack_into("<Q", data, 32, phoff)
    struct.pack_into("<H", data, 52, 64)  # ehsize
    struct.pack_into("<H", data, 54, phentsize)
    struct.pack_into("<H", data, 56, phnum)

    # PT_GNU_STACK. In ELF64 p_flags is immediately after p_type.
    struct.pack_into("<I", data, phoff, 0x6474E551)
    struct.pack_into("<I", data, phoff + 4, 0x7 if stack_executable else 0x6)
    if relro:
        second = phoff + phentsize
        struct.pack_into("<I", data, second, 0x6474E552)
        struct.pack_into("<I", data, second + 4, 0x4)
    return bytes(data)


def test_pe64_mitigation_flags_are_observations_without_false_candidates(tmp_path):
    # HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT | GUARD_CF
    binary = tmp_path / "safe.exe"
    binary.write_bytes(_pe64(dll_characteristics=0x0020 | 0x0040 | 0x0100 | 0x4000))
    report = analyze_binary_metadata(binary)
    assert report.format == "pe"
    assert report.architecture == "x86_64"
    assert report.bits == 64
    assert report.endianness == "little"
    assert report.image_type == "executable"
    assert report.mitigations == {
        "high_entropy_va": True,
        "aslr_dynamic_base": True,
        "dep_nx_compat": True,
        "control_flow_guard": True,
    }
    assert report.details["sections"] == 3
    assert report.candidates == ()
    assert len(report.sha256) == 64


def test_pe_missing_nx_and_aslr_emits_only_unverified_context_hypotheses(tmp_path):
    binary = tmp_path / "legacy.dll"
    binary.write_bytes(_pe64(dll_characteristics=0, is_dll=True))
    report = analyze_binary_metadata(binary)
    assert report.image_type == "dll"
    kinds = {row["scanner_metadata"]["analysis_kind"] for row in report.candidates}
    assert kinds == {"pe_nx_missing", "pe_aslr_missing"}
    assert all(row["validation_status"] == "unverified" for row in report.candidates)
    assert all(row["source"] == "aegis:binary-metadata" for row in report.candidates)
    assert all(row["severity"] == "low" for row in report.candidates)
    assert all(row["scanner_metadata"]["header_only"] is True for row in report.candidates)
    assert all(row["scanner_metadata"]["context_required"] is True for row in report.candidates)


def test_elf64_non_executable_stack_relro_and_pie_are_observations(tmp_path):
    binary = tmp_path / "safe.elf"
    binary.write_bytes(_elf64(stack_executable=False, relro=True, elf_type=3))
    report = analyze_binary_metadata(binary)
    assert report.format == "elf"
    assert report.architecture == "x86_64"
    assert report.bits == 64
    assert report.image_type == "shared_or_pie"
    assert report.mitigations == {
        "pie_or_shared": True,
        "gnu_relro_segment": True,
        "non_executable_stack": True,
    }
    assert report.details["program_header_count"] == 2
    assert report.candidates == ()


def test_elf_executable_stack_emits_medium_unverified_hypothesis(tmp_path):
    binary = tmp_path / "unsafe.elf"
    binary.write_bytes(_elf64(stack_executable=True, relro=False, elf_type=2))
    report = analyze_binary_metadata(binary)
    assert report.image_type == "executable"
    assert report.mitigations["pie_or_shared"] is False
    assert report.mitigations["gnu_relro_segment"] is False
    assert report.mitigations["non_executable_stack"] is False
    assert len(report.candidates) == 1
    row = report.candidates[0]
    assert row["scanner_metadata"]["analysis_kind"] == "elf_executable_stack"
    assert row["validation_status"] == "unverified"
    assert row["severity"] == "medium"
    assert row["source"] == "aegis:binary-metadata"


def test_architecture_maps_arm_and_big_endian_elf(tmp_path):
    data = bytearray(_elf64(stack_executable=False, machine=183))
    data[5] = 2
    # Rebuild the header/program headers in big endian after changing EI_DATA.
    struct.pack_into(">HHI", data, 16, 3, 183, 1)
    struct.pack_into(">Q", data, 32, 64)
    struct.pack_into(">H", data, 52, 64)
    struct.pack_into(">H", data, 54, 56)
    struct.pack_into(">H", data, 56, 2)
    struct.pack_into(">I", data, 64, 0x6474E551)
    struct.pack_into(">I", data, 68, 0x6)
    struct.pack_into(">I", data, 120, 0x6474E552)
    struct.pack_into(">I", data, 124, 0x4)
    binary = tmp_path / "arm64-be.elf"
    binary.write_bytes(data)
    report = analyze_binary_metadata(binary)
    assert report.architecture == "aarch64"
    assert report.endianness == "big"


def test_truncated_invalid_and_unsupported_images_fail_closed(tmp_path):
    truncated_pe = tmp_path / "bad.exe"
    blob = bytearray(80)
    blob[:2] = b"MZ"
    struct.pack_into("<I", blob, 0x3C, 0x1000)
    truncated_pe.write_bytes(blob)
    with pytest.raises(BinaryMetadataError, match="outside the bounded header window"):
        analyze_binary_metadata(truncated_pe)

    truncated_elf = tmp_path / "bad.elf"
    truncated_elf.write_bytes(b"\x7fELF" + b"\x00" * 10)
    with pytest.raises(BinaryMetadataError, match="unsupported binary format|ELF"):
        analyze_binary_metadata(truncated_elf)

    unknown = tmp_path / "blob.bin"
    unknown.write_bytes(b"not-a-binary-format")
    with pytest.raises(BinaryMetadataError, match="unsupported binary format"):
        analyze_binary_metadata(unknown)


def test_empty_binary_is_rejected(tmp_path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    with pytest.raises(BinaryMetadataError, match="size is outside"):
        analyze_binary_metadata(empty)
