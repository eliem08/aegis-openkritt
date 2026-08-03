from __future__ import annotations

import hashlib
import io
import json

import pytest
from cryptography.fernet import Fernet

from aegis.production.backup import BackupError, decrypt_stream, encrypt_stream
from aegis.production.drills import DrillResult, render_markdown, verdict
from aegis.production.releases import ReleaseLockError, load_release_lock, verify_locked_executables

PIN = "b" * 64


def write_lock(tmp_path, release):
    path = tmp_path / "lock.json"
    path.write_text(json.dumps({"schema": 1, "releases": [release]}), encoding="utf-8")
    return path


def release(**changes):
    value = {
        "name": "scanner", "version": "1.2.3", "sha256": PIN,
        "image": f"registry.example/scanner@sha256:{PIN}",
        "license_reviewed": True, "output_schema": "aegis.v1",
    }
    value.update(changes)
    return value


def test_release_lock_loads_only_complete_pinned_reviewed_entries(tmp_path):
    locked = load_release_lock(str(write_lock(tmp_path, release())))
    assert locked["scanner"].version == "1.2.3"
    for changes in ({"image": "scanner:latest"}, {"license_reviewed": False}, {"sha256": "bad"}):
        with pytest.raises((ReleaseLockError, ValueError)):
            load_release_lock(str(write_lock(tmp_path, release(**changes))))


def test_runtime_executable_checksum_is_verified(tmp_path):
    executable = tmp_path / "scanner"
    executable.write_bytes(b"approved binary")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    path = write_lock(tmp_path, release(sha256=digest, executable_path=str(executable)))
    assert verify_locked_executables(str(path))["scanner"].sha256 == digest
    executable.write_bytes(b"tampered")
    with pytest.raises(ReleaseLockError, match="checksum mismatch"):
        verify_locked_executables(str(path))


def test_encrypted_backup_stream_round_trip_and_tamper_rejection():
    fernet = Fernet(Fernet.generate_key())
    source = io.BytesIO((b"database archive" * 100000))
    encrypted = io.BytesIO()
    checksum = encrypt_stream(source, encrypted, fernet)
    assert checksum == hashlib.sha256(encrypted.getvalue()).hexdigest()
    restored = io.BytesIO()
    encrypted.seek(0)
    decrypt_stream(encrypted, restored, fernet)
    assert restored.getvalue() == b"database archive" * 100000
    damaged = bytearray(encrypted.getvalue())
    damaged[-1] ^= 1
    with pytest.raises(BackupError, match="authentication"):
        decrypt_stream(io.BytesIO(damaged), io.BytesIO(), fernet)


def test_drill_verdict_rejects_failure_and_not_configured():
    passing = [DrillResult("a", "pass", "ok")]
    assert verdict(passing)
    assert not verdict(passing + [DrillResult("b", "not_configured", "missing")])
    assert not verdict(passing + [DrillResult("c", "fail", "down")])
    assert verdict(passing + [DrillResult("optional", "not_configured", "missing", required=False)])


def test_markdown_report_escapes_table_content():
    report = render_markdown([DrillResult("gate", "fail", "bad | value\nnext", duration_ms=3)])
    assert "bad \\| value next" in report
