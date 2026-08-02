import pytest

from aegis.policy import HmacSignatureVerifier, RejectAllVerifier, canonical_bytes


def test_canonical_bytes_excludes_signature_fields():
    payload = {"a": 1, "signature": "x", "signing_key_id": "k"}
    out = canonical_bytes(payload)
    assert b"signature" not in out
    assert b"signing_key_id" not in out
    assert b'"a":1' in out


def test_canonical_bytes_is_order_independent():
    a = canonical_bytes({"b": 2, "a": 1})
    b = canonical_bytes({"a": 1, "b": 2})
    assert a == b


def test_hmac_sign_and_verify_roundtrip():
    v = HmacSignatureVerifier({"kid": "secret"})
    payload = {"customer_id": "c", "n": 5}
    sig = v.sign(payload, "kid")
    assert v.verify(payload, sig, "kid")


def test_hmac_rejects_tampered_payload():
    v = HmacSignatureVerifier({"kid": "secret"})
    payload = {"customer_id": "c", "n": 5}
    sig = v.sign(payload, "kid")
    tampered = {"customer_id": "c", "n": 6}
    assert not v.verify(tampered, sig, "kid")


def test_hmac_rejects_unknown_key_and_missing_bits():
    v = HmacSignatureVerifier({"kid": "secret"})
    payload = {"n": 1}
    sig = v.sign(payload, "kid")
    assert not v.verify(payload, sig, "other-kid")
    assert not v.verify(payload, None, "kid")
    assert not v.verify(payload, sig, None)


def test_hmac_requires_at_least_one_key():
    with pytest.raises(ValueError):
        HmacSignatureVerifier({})


def test_reject_all_verifier():
    assert not RejectAllVerifier().verify({"n": 1}, "anything", "kid")
