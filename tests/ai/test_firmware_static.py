from __future__ import annotations

import struct

import pytest

from aegis.ai.jarvis.asset_capabilities import AssetKind
from aegis.ai.jarvis.asset_deep_capabilities import ARCH_DETECT
from aegis.ai.jarvis.asset_execution_router import execute_offline_asset_method
from aegis.ai.jarvis.asset_execution_ticket import (
    AssetExecutionTicketError,
    CapabilityAvailability,
    issue_offline_execution_ticket,
)
from aegis.ai.jarvis.firmware_static import FirmwareStaticError, analyze_firmware_static


def _elf32(machine: int, *, little=True) -> bytes:
    data = bytearray(64)
    data[0:4] = b"\x7fELF"
    data[4] = 1
    data[5] = 1 if little else 2
    data[6] = 1
    struct.pack_into("<H" if little else ">H", data, 16, 2)
    struct.pack_into("<H" if little else ">H", data, 18, machine)
    return bytes(data)


def test_static_firmware_detects_format_architecture_init_and_services(tmp_path):
    firmware = tmp_path / "router.bin"
    firmware.write_bytes(
        b"hsqs" + b"\x00" * 128 + _elf32(8) +
        b"\x00/sbin/init\x00BusyBox\x00dropbear\x00uhttpd\x00dnsmasq\x00"
    )
    report = analyze_firmware_static(firmware)
    assert "squashfs-le" in report.formats
    assert report.architectures == ("mips",)
    assert report.endianness == ("little",)
    assert report.embedded_elf[0].bits == 32
    assert "/sbin/init" in report.init_markers
    assert "busybox" in tuple(item.lower() for item in report.init_markers)
    assert {"dropbear-ssh", "uhttpd", "dnsmasq"} <= set(report.service_markers)
    assert len(report.sha256) == 64


def test_static_firmware_detects_big_endian_arm_like_elf_independently(tmp_path):
    firmware = tmp_path / "mixed.bin"
    firmware.write_bytes(b"prefix" + _elf32(40, little=False) + b"tail")
    report = analyze_firmware_static(firmware)
    assert report.architectures == ("arm",)
    assert report.endianness == ("big",)
    assert report.embedded_elf[0].machine_id == 40


def test_static_firmware_size_and_scan_limits_fail_closed(tmp_path):
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"x" * 8192)
    with pytest.raises(FirmwareStaticError, match="size limit"):
        analyze_firmware_static(firmware, maximum_file_bytes=4096)
    report = analyze_firmware_static(firmware, maximum_scan_bytes=4096)
    assert report.scan_bytes == 4096
    assert report.truncated_scan is True


def test_ticket_and_router_require_authorized_firmware_and_emit_observation_only(tmp_path):
    with pytest.raises(AssetExecutionTicketError, match="authorized_firmware"):
        issue_offline_execution_ticket(
            asset_kind=AssetKind.HARDWARE,
            method=ARCH_DETECT,
            scope_digest="scope:fw",
            availability=CapabilityAvailability(),
        )

    firmware = tmp_path / "router.bin"
    firmware.write_bytes(b"hsqs" + _elf32(8) + b"dropbear")
    ticket = issue_offline_execution_ticket(
        asset_kind=AssetKind.HARDWARE,
        method=ARCH_DETECT,
        scope_digest="scope:fw",
        availability=CapabilityAvailability(firmware_available=True),
    )
    outcome = execute_offline_asset_method(
        ARCH_DETECT,
        ticket=ticket,
        scope_digest="scope:fw",
        firmware_path=firmware,
    )
    assert outcome.candidates == ()
    assert outcome.observations[0].kind == "firmware_metadata"
    assert outcome.observations[0].data["architectures"] == ("mips",)
    assert outcome.provenance["verification_state"] == "observation"
