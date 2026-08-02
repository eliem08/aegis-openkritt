"""Versioned key management + envelope encryption (Phase 5).

Rotation keeps old data readable, rewrap re-seals under the active key, and a
missing or revoked key fails closed — never a plaintext fallback.
"""

from __future__ import annotations

import pytest

from aegis.api.crypto import generate_key
from aegis.keys import EnvelopeEncryptor, KeyRevoked, KeyRing, KeyUnavailable

SECRET = "database connection string with a token"


def ring(*key_ids):
    r = KeyRing()
    for kid in key_ids:
        r.add(kid, generate_key())
    return r


# --- envelope basics ---------------------------------------------------------

def test_envelope_names_its_key_and_round_trips():
    enc = EnvelopeEncryptor(ring("k1"))
    env = enc.encrypt(SECRET)
    assert env.startswith("k1:") and SECRET not in env      # not plaintext
    assert enc.decrypt(env) == SECRET
    assert EnvelopeEncryptor.key_id_of(env) == "k1"


def test_no_active_key_fails_closed():
    with pytest.raises(KeyUnavailable):
        EnvelopeEncryptor(KeyRing()).encrypt(SECRET)


# --- rotation ----------------------------------------------------------------

def test_rotation_keeps_old_data_readable_and_seals_new_data_with_the_new_key():
    r = ring("k1")
    enc = EnvelopeEncryptor(r)
    old_env = enc.encrypt(SECRET)                           # sealed with k1

    r.rotate("k2", generate_key())                          # k2 now active, k1 retained
    new_env = enc.encrypt(SECRET)
    assert new_env.startswith("k2:")
    # overlapping window: both still decrypt
    assert enc.decrypt(old_env) == SECRET and enc.decrypt(new_env) == SECRET


def test_rewrap_reseals_under_the_active_key():
    r = ring("k1")
    enc = EnvelopeEncryptor(r)
    env = enc.encrypt(SECRET)
    r.rotate("k2", generate_key())

    rewrapped = enc.rewrap(env)
    assert rewrapped.startswith("k2:") and enc.decrypt(rewrapped) == SECRET


# --- fail closed on missing / revoked ---------------------------------------

def test_missing_key_fails_closed_never_plaintext():
    enc = EnvelopeEncryptor(ring("k1"))
    env = enc.encrypt(SECRET)
    # a fresh ring without k1 cannot read it — and does not return the ciphertext
    other = EnvelopeEncryptor(ring("kX"))
    with pytest.raises(KeyUnavailable):
        other.decrypt(env)


def test_revoked_key_fails_closed():
    r = ring("k1", "k2")
    enc = EnvelopeEncryptor(r)
    env = enc.encrypt(SECRET)                               # sealed with k1 (first = active)
    r.revoke("k1")
    with pytest.raises(KeyRevoked):
        enc.decrypt(env)


def test_revoking_the_active_key_repoints_to_a_live_key():
    r = ring("k1", "k2")
    r.revoke("k1")                                          # k1 was active
    assert r.active.key_id == "k2"                          # never active-and-revoked


def test_revoking_every_key_leaves_no_active_key():
    r = ring("k1")
    r.revoke("k1")
    with pytest.raises(KeyUnavailable):
        _ = r.active


def test_envelope_without_a_key_id_is_rejected():
    with pytest.raises(Exception):
        EnvelopeEncryptor(ring("k1")).decrypt("no-key-id-here")


# --- adopting existing ciphertext -------------------------------------------

def test_existing_ciphertext_can_be_given_a_key_id():
    r = ring("k1")
    enc = EnvelopeEncryptor(r)
    # ciphertext produced directly by the k1 Fernet (no envelope prefix)
    raw = r.get("k1").encryptor.encrypt(SECRET)
    adopted = enc.adopt(raw, "k1")
    assert adopted == f"k1:{raw}" and enc.decrypt(adopted) == SECRET
