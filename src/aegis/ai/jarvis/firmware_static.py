"""Deterministic, non-executing firmware structure and architecture inspection.

The analyzer reads bytes only. It does not decompress, mount, deserialize, emulate, or execute
firmware content. Its purpose is to cheaply identify likely filesystem/container formats,
embedded ELF architectures/endianness, init markers, and common embedded network-service strings
so later *authorized* extraction/emulation work can be prioritized.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import asdict, dataclass
from pathlib import Path


class FirmwareStaticError(RuntimeError):
    pass


@dataclass(frozen=True)
class EmbeddedElf:
    offset: int
    bits: int
    endianness: str
    machine: str
    machine_id: int


@dataclass(frozen=True)
class FirmwareStaticReport:
    file_name: str
    size_bytes: int
    sha256: str
    formats: tuple[str, ...]
    architectures: tuple[str, ...]
    endianness: tuple[str, ...]
    embedded_elf: tuple[EmbeddedElf, ...]
    init_markers: tuple[str, ...]
    service_markers: tuple[str, ...]
    scan_bytes: int
    truncated_scan: bool

    def as_dict(self) -> dict:
        return {
            **asdict(self),
            "embedded_elf": [asdict(item) for item in self.embedded_elf],
        }


_FORMAT_MAGICS: tuple[tuple[bytes, str], ...] = (
    (b"hsqs", "squashfs-le"),
    (b"sqsh", "squashfs-be"),
    (b"UBI#", "ubi"),
    (b"\x85\x19", "jffs2-le"),
    (b"\x19\x85", "jffs2-be"),
    (b"\x45\x3d\xcd\x28", "cramfs-le"),
    (b"\x28\xcd\x3d\x45", "cramfs-be"),
    (b"PK\x03\x04", "zip"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"ustar", "tar"),
    (b"\x27\x05\x19\x56", "u-boot-uimage"),
    (b"\xd0\x0d\xfe\xed", "device-tree-blob"),
)

_MACHINE = {
    3: "x86",
    8: "mips",
    20: "powerpc",
    21: "powerpc64",
    40: "arm",
    62: "x86_64",
    183: "aarch64",
    243: "riscv",
}

_INIT_MARKERS = (
    b"/sbin/init",
    b"/etc/inittab",
    b"/lib/systemd/systemd",
    b"busybox",
    b"procd",
)

_SERVICE_MARKERS = {
    b"dropbear": "dropbear-ssh",
    b"sshd": "ssh",
    b"telnetd": "telnet",
    b"uhttpd": "uhttpd",
    b"lighttpd": "lighttpd",
    b"nginx": "nginx",
    b"boa": "boa-httpd",
    b"httpd": "httpd",
    b"dnsmasq": "dnsmasq",
    b"miniupnpd": "upnp",
    b"mosquitto": "mqtt",
}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _format_hits(data: bytes) -> tuple[str, ...]:
    hits: set[str] = set()
    for magic, label in _FORMAT_MAGICS:
        if magic == b"ustar":
            # POSIX tar magic is normally at offset 257 of a header, but embedded tar headers
            # may occur later. Byte search is still only a structural hint.
            if data.find(magic) >= 0:
                hits.add(label)
        elif data.find(magic) >= 0:
            hits.add(label)
    if len(data) >= 1082 and data[1080:1082] == b"\x53\xef":
        hits.add("ext-filesystem")
    return tuple(sorted(hits))


def _embedded_elf(data: bytes, maximum: int = 64) -> tuple[EmbeddedElf, ...]:
    output: list[EmbeddedElf] = []
    cursor = 0
    while len(output) < maximum:
        offset = data.find(b"\x7fELF", cursor)
        if offset < 0:
            break
        cursor = offset + 4
        if offset + 20 > len(data):
            continue
        elf_class = data[offset + 4]
        elf_data = data[offset + 5]
        if elf_class not in {1, 2} or elf_data not in {1, 2}:
            continue
        endian = "little" if elf_data == 1 else "big"
        fmt = "<H" if elf_data == 1 else ">H"
        try:
            machine_id = struct.unpack_from(fmt, data, offset + 18)[0]
        except struct.error:
            continue
        output.append(
            EmbeddedElf(
                offset=offset,
                bits=32 if elf_class == 1 else 64,
                endianness=endian,
                machine=_MACHINE.get(machine_id, f"elf-machine-{machine_id}"),
                machine_id=machine_id,
            )
        )
    return tuple(output)


def analyze_firmware_static(
    firmware_path: str | Path,
    *,
    maximum_scan_bytes: int = 64 * 1024 * 1024,
    maximum_file_bytes: int = 8 * 1024 * 1024 * 1024,
) -> FirmwareStaticReport:
    """Inspect firmware bytes without extraction or execution."""
    path = Path(firmware_path).expanduser().resolve()
    if not path.is_file():
        raise FirmwareStaticError("firmware must be an existing regular file")
    size = path.stat().st_size
    if size <= 0:
        raise FirmwareStaticError("firmware cannot be empty")
    if size > maximum_file_bytes:
        raise FirmwareStaticError("firmware exceeds the configured size limit")
    if not 4096 <= int(maximum_scan_bytes) <= 512 * 1024 * 1024:
        raise FirmwareStaticError("maximum_scan_bytes is outside the allowed range")

    with path.open("rb") as handle:
        data = handle.read(min(size, int(maximum_scan_bytes)))
    lower = data.lower()
    elf = _embedded_elf(data)
    architectures = tuple(sorted({item.machine for item in elf}))
    endian = tuple(sorted({item.endianness for item in elf}))
    init_markers = tuple(
        marker.decode("ascii", errors="ignore")
        for marker in _INIT_MARKERS
        if marker.lower() in lower
    )
    services = tuple(
        sorted(label for marker, label in _SERVICE_MARKERS.items() if marker.lower() in lower)
    )
    return FirmwareStaticReport(
        file_name=path.name,
        size_bytes=size,
        sha256=_sha256_file(path),
        formats=_format_hits(data),
        architectures=architectures,
        endianness=endian,
        embedded_elf=elf,
        init_markers=init_markers,
        service_markers=services,
        scan_bytes=len(data),
        truncated_scan=size > len(data),
    )
