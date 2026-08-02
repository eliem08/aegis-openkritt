"""Encryption at rest: sensitive columns are ciphertext on disk, plaintext in use."""

import json
import sqlite3
from datetime import datetime, timezone

import pytest

from aegis.api.crypto import FernetEncryptor, NullEncryptor, build_encryptor, generate_key
from aegis.api.persistence import SqliteRepository
from aegis.api.store import EngagementRecord


def test_fernet_roundtrip():
    enc = FernetEncryptor(generate_key())
    assert enc.decrypt(enc.encrypt("secret data")) == "secret data"
    assert enc.encrypt("secret data") != "secret data"


def test_build_encryptor_defaults_to_null():
    assert isinstance(build_encryptor(None), NullEncryptor)
    assert isinstance(build_encryptor(generate_key()), FernetEncryptor)


def test_null_encryptor_is_passthrough():
    n = NullEncryptor()
    assert n.encrypt("x") == "x" and n.decrypt("x") == "x"


def _raw_columns(db_path: str) -> tuple[str, str]:
    conn = sqlite3.connect(db_path)
    try:
        auth = conn.execute("SELECT auth_json FROM engagements").fetchone()[0]
        audit = conn.execute("SELECT record FROM audit").fetchone()
        return auth, (audit[0] if audit else "")
    finally:
        conn.close()


def test_encrypted_repo_stores_ciphertext_but_reads_plaintext(tmp_path):
    db = str(tmp_path / "enc.db")
    key = generate_key()
    repo = SqliteRepository(db, encryptor=FernetEncryptor(key))

    secret_target = "api.super-secret-customer.test"
    repo.save_engagement(EngagementRecord(
        id="e1", authorization={"targets": [secret_target]}, status="active",
        created_at=datetime.now(timezone.utc),
    ))
    repo.append_audit("e1", {"target": secret_target, "verdict": "allow"})
    repo.close()

    # On disk: the sensitive value must NOT appear in plaintext.
    raw_auth, raw_audit = _raw_columns(db)
    assert secret_target not in raw_auth
    assert secret_target not in raw_audit

    # Read back through a repo with the same key: plaintext restored.
    repo2 = SqliteRepository(db, encryptor=FernetEncryptor(key))
    assert repo2.get_engagement("e1").authorization["targets"] == [secret_target]
    assert repo2.recent_audit("e1", 10)[0]["target"] == secret_target


def test_plaintext_when_no_key(tmp_path):
    db = str(tmp_path / "plain.db")
    repo = SqliteRepository(db)  # NullEncryptor
    repo.save_engagement(EngagementRecord(
        id="e1", authorization={"targets": ["api.example.test"]}, status="active",
        created_at=datetime.now(timezone.utc),
    ))
    repo.close()
    raw_auth, _ = _raw_columns(db)
    assert "api.example.test" in raw_auth  # plaintext by default (backwards compatible)


def test_wrong_key_cannot_decrypt(tmp_path):
    db = str(tmp_path / "enc.db")
    SqliteRepository(db, encryptor=FernetEncryptor(generate_key())).save_engagement(
        EngagementRecord(id="e1", authorization={"x": 1}, status="active",
                         created_at=datetime.now(timezone.utc))
    )
    other = SqliteRepository(db, encryptor=FernetEncryptor(generate_key()))  # different key
    with pytest.raises(Exception):
        other.get_engagement("e1")
