"""Executable triage: format, entropy, secrets, dependencies, and bundle unpacking.

All of this runs on a local artifact the operator already downloaded — nothing here
fetches a binary, and nothing here executes one. The interesting output is usually
the last technique: an Electron/ASAR bundle unpacked back into plain JavaScript,
which then goes through the existing source-review lane where the repository's
detectors and taint tracing already work well.
"""

from __future__ import annotations

import json
import math
import re
import struct
import zipfile
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterator

from .context import LaneContext
from .results import (
    Observation,
    TechniqueResult,
    deduplicate,
    executed,
    now,
    unavailable,
    waiting,
)

#: Read at most this many bytes. Binaries can be very large and triage does not
#: need all of one; the cap is reported so a truncated scan is never mistaken for
#: a complete one.
MAX_READ_BYTES = 64 * 1024 * 1024

MIN_STRING_LENGTH = 6

_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"\xca\xfe\xba\xbe", "macho-fat"),
    (b"\xcf\xfa\xed\xfe", "macho64"),
    (b"\xce\xfa\xed\xfe", "macho32"),
    (b"PK\x03\x04", "zip"),
    (b"\x04\x22\x4d\x18", "lz4"),
    (b"\x7fELF", "elf"),
)

#: Section names left behind by common packers. Their presence is an indicator, not
#: proof — some legitimate installers use the same compressors.
PACKER_MARKERS: tuple[tuple[bytes, str], ...] = (
    (b"UPX!", "UPX"),
    (b".aspack", "ASPack"),
    (b"MPRESS", "MPRESS"),
    (b".themida", "Themida"),
    (b"VMProtect", "VMProtect"),
    (b"PyInstaller", "PyInstaller"),
    (b"_MEIPASS", "PyInstaller"),
    (b"pkg/prelude", "Node SEA/pkg"),
    (b"electron.asar", "Electron"),
)

#: Credential-shaped literals. Each pattern is deliberately specific: a generic
#: "looks like base64" rule produces far more noise than an operator can triage.
SECRET_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("aws-access-key-id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "high"),
    ("google-api-key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "high"),
    ("slack-token", r"\bxox[baprs]-[0-9A-Za-z\-]{10,60}\b", "high"),
    ("github-token", r"\bgh[pousr]_[0-9A-Za-z]{36,}\b", "high"),
    ("stripe-key", r"\b[sr]k_live_[0-9A-Za-z]{20,}\b", "high"),
    ("private-key-block", r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", "high"),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", "medium"),
    ("bearer-literal", r"(?i)\b(?:authorization|bearer)\s*[:=]\s*[A-Za-z0-9_\-\.]{20,}", "medium"),
    ("connection-string", r"(?i)\b(?:postgres|mysql|mongodb(?:\+srv)?|redis|amqp)://"
                         r"[^\s:@/]+:[^\s:@/]+@[^\s/]+", "high"),
)

_ENDPOINT = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,200}")
_VERSION_BANNER = re.compile(
    rb"\b([A-Za-z][A-Za-z0-9_.+-]{2,40})[/ ]v?(\d+\.\d+(?:\.\d+){0,2})\b",
)
_LINKED_LIBRARY = re.compile(rb"\b([A-Za-z0-9_.+-]{3,60}\.(?:so(?:\.\d+)*|dll|dylib))\b")


@dataclass(frozen=True, slots=True)
class BinaryProfile:
    """Structural facts about an artifact, independent of any finding."""

    path: str
    size_bytes: int
    format: str
    architecture: str
    entropy: float
    truncated: bool
    packers: tuple[str, ...] = ()
    signed_indicators: tuple[str, ...] = ()

    def document(self) -> dict[str, Any]:
        return asdict(self)


def _artifact(context: LaneContext) -> Path | None:
    if context.artifact_path is None:
        return None
    path = Path(context.artifact_path)
    return path if path.is_file() else None


def _read(path: Path) -> tuple[bytes, bool]:
    size = path.stat().st_size
    with path.open("rb") as handle:
        payload = handle.read(MAX_READ_BYTES)
    return payload, size > MAX_READ_BYTES


def shannon_entropy(payload: bytes) -> float:
    """Bits of entropy per byte. Above ~7.2 usually means packed or encrypted."""
    if not payload:
        return 0.0
    counts = Counter(payload)
    total = len(payload)
    return -sum(
        (count / total) * math.log2(count / total) for count in counts.values()
    )


def detect_format(payload: bytes) -> tuple[str, str]:
    """Return ``(format, architecture)`` from the artifact's magic bytes."""
    for magic, name in _MAGIC:
        if payload.startswith(magic):
            if name == "elf" and len(payload) > 18:
                machine = struct.unpack_from("<H", payload, 18)[0]
                architecture = {
                    0x03: "x86", 0x3E: "x86-64", 0x28: "arm", 0xB7: "aarch64",
                    0xF3: "riscv",
                }.get(machine, f"elf-machine-{machine:#x}")
                return "elf", architecture
            if name == "pe" and len(payload) > 0x40:
                offset = struct.unpack_from("<I", payload, 0x3C)[0]
                if 0 < offset < len(payload) - 6 and payload[offset:offset + 4] == b"PE\0\0":
                    machine = struct.unpack_from("<H", payload, offset + 4)[0]
                    architecture = {
                        0x014C: "x86", 0x8664: "x86-64", 0xAA64: "arm64",
                    }.get(machine, f"pe-machine-{machine:#x}")
                    return "pe", architecture
                return "pe", "unknown"
            return name, "unknown"
    if payload[:4] in {b"\xde\xc0\x17\x0b"}:
        return "llvm-bitcode", "unknown"
    return "unknown", "unknown"


def iter_strings(payload: bytes, minimum: int = MIN_STRING_LENGTH) -> Iterator[str]:
    """Yield printable ASCII runs, the classic ``strings`` behaviour."""
    current: list[int] = []
    for byte in payload:
        if 0x20 <= byte < 0x7F:
            current.append(byte)
            continue
        if len(current) >= minimum:
            yield bytes(current).decode("ascii")
        current = []
    if len(current) >= minimum:
        yield bytes(current).decode("ascii")


def profile_binary(path: Path) -> BinaryProfile:
    """Build the structural profile without executing or unpacking anything."""
    payload, truncated = _read(path)
    binary_format, architecture = detect_format(payload)
    packers = tuple(sorted({
        label for marker, label in PACKER_MARKERS if marker in payload
    }))
    signed = []
    if b"wintrust.dll" in payload or b"\x00Authenticode\x00" in payload:
        signed.append("authenticode-reference")
    if b"CodeDirectory" in payload or b"com.apple.security" in payload:
        signed.append("macos-code-signature")
    if b".note.gnu.build-id" in payload:
        signed.append("gnu-build-id")
    return BinaryProfile(
        str(path), path.stat().st_size, binary_format, architecture,
        round(shannon_entropy(payload), 4), truncated, packers, tuple(signed),
    )


# ------------------------------------------------------------------ techniques

def binary_triage(context: LaneContext) -> TechniqueResult:
    """Identify format, architecture, entropy, packing, and signing indicators."""
    technique = "binary-triage"
    started = now()
    path = _artifact(context)
    if path is None:
        return waiting(
            technique, context.asset,
            "no local artifact supplied; download the executable yourself and pass "
            "--artifact (Aegis does not fetch or execute binaries)",
        )
    profile = profile_binary(path)
    observations: list[Observation] = []
    if profile.packers:
        observations.append(Observation(
            technique, "Artifact shows packer or bundler markers", "info", path.name,
            evidence={"packers": list(profile.packers), "entropy": profile.entropy},
            weakness="packed-binary",
            recommendation="unpack before drawing conclusions; packing alone is not a bug",
        ))
    if profile.entropy > 7.2 and not profile.packers:
        observations.append(Observation(
            technique, "Uniformly high entropy without a recognized packer", "info",
            path.name, evidence={"entropy": profile.entropy, "format": profile.format},
            weakness="opaque-binary",
            recommendation="likely compressed or encrypted; static string analysis will be thin",
        ))
    if profile.format in {"pe", "macho64", "macho32"} and not profile.signed_indicators:
        observations.append(Observation(
            technique, "No code-signature indicators found in a distributed executable",
            "low", path.name, evidence={"format": profile.format},
            weakness="unsigned-distribution",
            recommendation="confirm with the platform's signature tool before reporting; "
                           "absence of markers in a truncated read is not proof",
        ))
    return executed(
        technique, context.asset, deduplicate(observations), tool="aegis-binary-triage",
        started_at=started, metadata=profile.document(),
    )


def embedded_secret_scan(context: LaneContext) -> TechniqueResult:
    """Extract credential-shaped literals and hardcoded endpoints from the artifact."""
    technique = "embedded-secret-scan"
    started = now()
    path = _artifact(context)
    if path is None:
        return waiting(technique, context.asset, "no local artifact supplied")
    payload, truncated = _read(path)
    text = "\n".join(iter_strings(payload))
    observations: list[Observation] = []
    matches: dict[str, int] = {}
    for label, pattern, severity in SECRET_PATTERNS:
        found = re.findall(pattern, text)
        if not found:
            continue
        matches[label] = len(found)
        observations.append(Observation(
            technique, f"Embedded {label.replace('-', ' ')} literal", severity, path.name,
            # The value itself is never recorded — a report must not carry a live key.
            evidence={"secret_class": label, "occurrences": len(found),
                      "value_recorded": False},
            weakness="hardcoded-credential",
            recommendation="verify the credential is live and in scope before reporting; "
                           "redact the value in the report body",
        ))
    endpoints = sorted({
        item.decode("ascii", "replace") for item in _ENDPOINT.findall(payload)
    })
    internal = [
        item for item in endpoints
        if any(token in item for token in
               ("localhost", "127.0.0.1", "10.", "192.168.", ".internal", ".local", ":8080"))
    ]
    if internal:
        observations.append(Observation(
            technique, "Internal endpoints referenced by a distributed binary", "info",
            path.name, evidence={"internal_endpoints": internal[:50]},
            weakness="internal-surface-disclosure",
            recommendation="these hostnames are attack-surface leads, not findings",
        ))
    return executed(
        technique, context.asset, deduplicate(observations), tool="aegis-strings",
        started_at=started,
        metadata={"secret_classes": matches, "endpoint_count": len(endpoints),
                  "endpoints": endpoints[:200], "truncated_read": truncated},
    )


def dependency_extraction(context: LaneContext) -> TechniqueResult:
    """Recover linked libraries and version banners, preferring syft when installed."""
    technique = "dependency-extraction"
    started = now()
    path = _artifact(context)
    if path is None:
        return waiting(technique, context.asset, "no local artifact supplied")

    tool = context.resolver.resolve("syft")
    if tool.usable:
        code, stdout, stderr = context.resolver.run(
            tool, ["-o", "json", str(path)], mounts=[str(path.parent)], timeout=600.0,
        )
        if code == 0 and stdout.strip():
            packages = parse_syft(stdout)
            return executed(
                technique, context.asset, (), tool="syft", tool_version=tool.version,
                started_at=started,
                metadata={"packages": packages[:500], "package_count": len(packages),
                          "location": tool.location.value},
            )
        # Fall through to the built-in extractor rather than reporting nothing.
        fallback_reason = f"syft did not produce output ({stderr.strip()[:200]})"
    else:
        fallback_reason = f"syft unavailable ({tool.reason})"

    payload, truncated = _read(path)
    libraries = sorted({
        item.decode("ascii", "replace") for item in _LINKED_LIBRARY.findall(payload)
    })
    banners = sorted({
        f"{name.decode('ascii', 'replace')} {version.decode('ascii', 'replace')}"
        for name, version in _VERSION_BANNER.findall(payload)
    })
    return executed(
        technique, context.asset, (), tool="aegis-strings", started_at=started,
        reason=f"{fallback_reason}; used the built-in string extractor, which recovers "
               "linked library names and version banners but not a full SBOM",
        metadata={"linked_libraries": libraries[:200], "version_banners": banners[:200],
                  "truncated_read": truncated, "degraded": True},
    )


def parse_syft(payload: str) -> list[dict[str, str]]:
    """Normalize a syft JSON document into name/version/type rows."""
    try:
        document = json.loads(payload)
    except json.JSONDecodeError:
        return []
    artifacts = document.get("artifacts") if isinstance(document, dict) else None
    if not isinstance(artifacts, list):
        return []
    return [
        {
            "name": str(item.get("name") or ""),
            "version": str(item.get("version") or ""),
            "type": str(item.get("type") or ""),
        }
        for item in artifacts if isinstance(item, dict) and item.get("name")
    ]


def bundle_unpack(context: LaneContext) -> TechniqueResult:
    """Unpack an ASAR or zip-based bundle so its JavaScript reaches the source lane."""
    technique = "bundle-unpack"
    started = now()
    path = _artifact(context)
    if path is None:
        return waiting(technique, context.asset, "no local artifact supplied")
    destination = Path(
        context.workspace or path.parent,
    ) / f"{path.stem}-unpacked"

    try:
        if zipfile.is_zipfile(path):
            extracted = _extract_zip(path, destination)
            kind = "zip"
        elif _is_asar(path):
            extracted = extract_asar(path, destination)
            kind = "asar"
        else:
            return executed(
                technique, context.asset, (), tool="aegis-asar", started_at=started,
                reason="artifact is neither a zip archive nor an ASAR bundle; "
                       "nothing to route back to the source lane",
                metadata={"unpacked": False},
            )
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        return unavailable(
            technique, context.asset,
            f"bundle could not be unpacked: {type(exc).__name__}: {exc}", tool="aegis-asar",
        )

    scripts = sorted(
        str(item.relative_to(destination)) for item in destination.rglob("*")
        if item.is_file() and item.suffix.lower() in {".js", ".mjs", ".cjs", ".ts", ".json"}
    )
    observations = [Observation(
        technique, "Bundle contains application JavaScript reachable by source review",
        "info", path.name,
        evidence={"unpacked_to": str(destination), "script_count": len(scripts),
                  "sample": scripts[:30]},
        weakness="unpacked-source-available",
        recommendation=(
            "re-run the hunt with --asset-type source_code --artifact "
            f"{destination} so the existing scanner and taint lane covers it"
        ),
    )] if scripts else []
    return executed(
        technique, context.asset, observations, tool="aegis-asar", started_at=started,
        metadata={"unpacked": True, "kind": kind, "destination": str(destination),
                  "file_count": extracted, "script_count": len(scripts)},
    )


def _safe_destination(root: Path, name: str) -> Path:
    """Resolve an archive member under ``root``, refusing traversal (zip-slip)."""
    target = (root / name).resolve()
    if not str(target).startswith(str(root.resolve())):
        raise ValueError(f"archive member escapes the extraction root: {name!r}")
    return target


def _extract_zip(path: Path, destination: Path) -> int:
    destination.mkdir(parents=True, exist_ok=True)
    count = 0
    with zipfile.ZipFile(path) as archive:
        for member in archive.namelist():
            if member.endswith("/"):
                continue
            target = _safe_destination(destination, member)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, target.open("wb") as handle:
                handle.write(source.read())
            count += 1
    return count


def _is_asar(path: Path) -> bool:
    with path.open("rb") as handle:
        header = handle.read(16)
    # ASAR is a pickle-framed header: four little-endian uint32 sizes then JSON.
    return len(header) == 16 and header[:4] == b"\x04\x00\x00\x00" and header[12:16] != b""


def extract_asar(path: Path, destination: Path) -> int:
    """Extract an Electron ASAR archive using its documented header layout."""
    with path.open("rb") as handle:
        prefix = handle.read(16)
        if len(prefix) < 16:
            raise ValueError("file is too short to be an ASAR archive")
        header_size = struct.unpack_from("<I", prefix, 12)[0]
        raw = handle.read(header_size)
        try:
            index = json.loads(raw.split(b"\x00", 1)[0].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"ASAR header is not valid JSON: {exc}") from exc
        base = 16 + header_size
        base += (4 - base % 4) % 4  # header is padded to a 4-byte boundary
        destination.mkdir(parents=True, exist_ok=True)
        return _write_asar_files(handle, index, destination, base)


def _write_asar_files(handle, node: Any, root: Path, base: int, prefix: str = "") -> int:
    if not isinstance(node, dict):
        return 0
    files = node.get("files")
    if not isinstance(files, dict):
        return 0
    count = 0
    for name, entry in files.items():
        if not isinstance(entry, dict):
            continue
        member = f"{prefix}{name}"
        if "files" in entry:
            count += _write_asar_files(handle, entry, root, base, prefix=f"{member}/")
            continue
        try:
            offset = int(entry.get("offset", 0))
            size = int(entry.get("size", 0))
        except (TypeError, ValueError):
            continue
        target = _safe_destination(root, member)
        target.parent.mkdir(parents=True, exist_ok=True)
        handle.seek(base + offset)
        target.write_bytes(handle.read(size))
        count += 1
    return count


__all__ = [
    "BinaryProfile",
    "MAX_READ_BYTES",
    "PACKER_MARKERS",
    "SECRET_PATTERNS",
    "binary_triage",
    "bundle_unpack",
    "dependency_extraction",
    "detect_format",
    "embedded_secret_scan",
    "extract_asar",
    "iter_strings",
    "parse_syft",
    "profile_binary",
    "shannon_entropy",
]
