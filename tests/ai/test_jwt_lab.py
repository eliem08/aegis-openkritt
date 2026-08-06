"""Offline JWT lab — decode, analyze, crack, forge, and finding-PoC generation."""

from __future__ import annotations

from aegis.ai import jwt_lab


def _hs256(payload, secret):
    return jwt_lab.forge(payload, alg="HS256", secret=secret)


def test_decode_roundtrip():
    tok = _hs256({"user": "bob"}, "s3cr3t")
    d = jwt_lab.decode(tok)
    assert d.alg == "HS256" and d.payload["user"] == "bob" and d.signature


def test_decode_rejects_garbage():
    import pytest
    with pytest.raises(ValueError):
        jwt_lab.decode("not-a-jwt")


def test_analyze_flags_alg_none():
    tok = jwt_lab.forge({"user": "admin"}, alg="none")
    ids = {w.id for w in jwt_lab.analyze(tok)}
    assert "alg-none" in ids and "no-exp" in ids


def test_analyze_flags_jku_and_kid():
    tok = jwt_lab.forge({"user": "x", "exp": 9999999999}, alg="HS256", secret="k",
                        header={"kid": "1", "jku": "https://evil/keys"})
    ids = {w.id for w in jwt_lab.analyze(tok)}
    assert "kid-present" in ids and "jku-x5u" in ids


def test_crack_hmac_finds_secret():
    tok = _hs256({"user": "admin"}, "letmein")
    assert jwt_lab.crack_hmac(tok, ["nope", "letmein", "other"]) == "letmein"


def test_crack_hmac_none_when_absent():
    tok = _hs256({"user": "admin"}, "z9-super-secret")
    assert jwt_lab.crack_hmac(tok, ["a", "b", "c"]) is None


def test_forge_none_has_empty_signature():
    tok = jwt_lab.forge({"role": "admin"}, alg="none")
    assert tok.endswith(".") and jwt_lab.decode(tok).alg == "none"


def test_forge_hs256_verifies_with_secret():
    tok = jwt_lab.forge({"role": "admin"}, alg="HS256", secret="k")
    assert jwt_lab.crack_hmac(tok, ["k"]) == "k"


def test_forge_alg_confusion_signs_with_pubkey():
    orig = jwt_lab.forge({"user": "bob"}, alg="HS256", secret="orig")
    pub = "-----BEGIN PUBLIC KEY-----\nMFkw...fake...\n-----END PUBLIC KEY-----"
    forged = jwt_lab.forge_alg_confusion(orig, pub, mutate={"user": "admin"})
    d = jwt_lab.decode(forged)
    assert d.alg == "HS256" and d.payload["user"] == "admin"
    # server that (wrongly) verifies HS256 with the public key would accept it
    assert jwt_lab.crack_hmac(forged, [pub]) == pub


def test_extract_secret_from_source():
    src = 'const JWT_SECRET = "hunter2-hardcoded";\njwt.sign(p, JWT_SECRET)'
    assert jwt_lab.extract_secret(src) == "hunter2-hardcoded"


def test_extract_secret_skips_env():
    src = 'const secret = process.env.JWT_SECRET;'
    assert jwt_lab.extract_secret(src) == ""


def test_poc_uses_hardcoded_secret_when_present():
    src = 'jwt_secret = "leaked-key-123"'
    poc = jwt_lab.poc_for_finding(source=src)
    assert poc["attack"] == "hardcoded-secret" and poc["secret_used"] == "leaked-key-123"
    # the forged token really verifies with the leaked secret
    assert jwt_lab.crack_hmac(poc["forged_token"], ["leaked-key-123"]) == "leaked-key-123"
    assert jwt_lab.decode(poc["forged_token"]).payload.get("role") == "admin"


def test_poc_falls_back_to_alg_none():
    poc = jwt_lab.poc_for_finding(source="no secret here")
    assert poc["attack"] == "alg-none"
    assert jwt_lab.decode(poc["forged_token"]).alg == "none"
