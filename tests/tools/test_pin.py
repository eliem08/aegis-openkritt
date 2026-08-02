"""Binary pinning tool + runtime digest injection (Phase 5).

The mechanism is tested against synthetic 'release' files (no network): pinning
computes and records a digest, fails closed on a publisher mismatch, and a pinned
adapter verifies a matching on-disk binary but rejects a tampered one.
"""

from __future__ import annotations

import hashlib

import pytest

from aegis.adapters import SubfinderAdapter, discovery_adapters
from aegis.process import BinaryVerificationError
from aegis.tools.pin import (
    PinMismatch,
    digest_file,
    load_pins,
    pin_from_file,
    save_pins,
    verify_against_pin,
)


def write_binary(path, content=b"fake-subfinder-release-v2.6.6"):
    path.write_bytes(content)
    return hashlib.sha256(content).hexdigest()


# --- pinning -----------------------------------------------------------------

def test_pin_records_the_computed_digest(tmp_path):
    binary = tmp_path / "subfinder"
    expected = write_binary(binary)
    pinned = pin_from_file(str(binary), tool="subfinder", version="2.6.6")
    assert pinned.sha256 == expected and pinned.tool == "subfinder"


def test_pin_fails_closed_on_publisher_mismatch(tmp_path):
    binary = tmp_path / "subfinder"
    write_binary(binary, b"TAMPERED")
    with pytest.raises(PinMismatch):
        pin_from_file(str(binary), tool="subfinder", version="2.6.6", expected_sha256="00" * 32)


def test_pin_accepts_a_matching_publisher_digest(tmp_path):
    binary = tmp_path / "subfinder"
    digest = write_binary(binary)
    pinned = pin_from_file(str(binary), tool="subfinder", version="2.6.6", expected_sha256=digest)
    assert pinned.sha256 == digest


def test_pins_round_trip_through_a_file(tmp_path):
    binary = tmp_path / "nuclei"
    write_binary(binary, b"nuclei-3.3.0")
    pinned = pin_from_file(str(binary), tool="nuclei", version="3.3.0")
    save_pins([pinned], str(tmp_path / "pins.json"))
    loaded = load_pins(str(tmp_path / "pins.json"))
    assert loaded["nuclei"].sha256 == pinned.sha256


def test_verify_against_pin_detects_tampering(tmp_path):
    binary = tmp_path / "gau"
    write_binary(binary, b"gau-2.2.4")
    pins = {"gau": pin_from_file(str(binary), tool="gau", version="2.2.4")}
    assert verify_against_pin(str(binary), "gau", pins) is True
    binary.write_bytes(b"gau-2.2.4-BACKDOORED")
    assert verify_against_pin(str(binary), "gau", pins) is False


def test_verify_unpinned_tool_fails_closed(tmp_path):
    binary = tmp_path / "x"
    write_binary(binary)
    from aegis.tools.pin import PinError

    with pytest.raises(PinError):
        verify_against_pin(str(binary), "unpinned", {})


# --- runtime injection into adapters ----------------------------------------

def test_pinned_adapter_verifies_a_matching_binary(tmp_path):
    binary = tmp_path / "subfinder"
    write_binary(binary)
    pins = {"subfinder": pin_from_file(str(binary), tool="subfinder", version="2.6.6")}

    adapter = discovery_adapters(pins=pins, executable=str(binary))["subfinder"]
    # resolve_executable runs verify_binary against the injected pinned digest
    assert adapter.resolve_executable() == str(binary)


def test_pinned_adapter_rejects_a_tampered_binary(tmp_path):
    binary = tmp_path / "subfinder"
    write_binary(binary)
    pins = {"subfinder": pin_from_file(str(binary), tool="subfinder", version="2.6.6")}
    adapter = discovery_adapters(pins=pins, executable=str(binary))["subfinder"]
    binary.write_bytes(b"tampered-after-pinning")
    with pytest.raises(BinaryVerificationError):
        adapter.resolve_executable()


def test_unpinned_registry_still_fails_closed(tmp_path):
    binary = tmp_path / "subfinder"
    write_binary(binary)
    # no pins -> code-shipped empty digest -> refuses to run
    from aegis.adapters import ToolUnavailable

    adapter = discovery_adapters(executable=str(binary))["subfinder"]
    with pytest.raises(ToolUnavailable):
        adapter.resolve_executable()
