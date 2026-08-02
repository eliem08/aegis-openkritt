"""Ed25519 asymmetric authorization signatures (P0 #8)."""

from datetime import datetime, timedelta, timezone

import pytest

from aegis.policy import (
    ActionRequest,
    Authorization,
    Ed25519SignatureVerifier,
    Ed25519Signer,
    PolicyEngine,
    Verdict,
)


def test_sign_and_verify_roundtrip():
    signer = Ed25519Signer.generate("kid-1")
    payload = {"customer_id": "c", "n": 5}
    sig = signer.sign(payload)
    assert signer.verifier().verify(payload, sig, "kid-1")


def test_tampered_payload_rejected():
    signer = Ed25519Signer.generate("kid-1")
    sig = signer.sign({"n": 5})
    assert not signer.verifier().verify({"n": 6}, sig, "kid-1")


def test_wrong_key_id_rejected():
    signer = Ed25519Signer.generate("kid-1")
    sig = signer.sign({"n": 5})
    assert not signer.verifier().verify({"n": 5}, sig, "other")


def test_bad_signature_hex_rejected():
    signer = Ed25519Signer.generate("kid-1")
    v = signer.verifier()
    assert not v.verify({"n": 5}, "not-hex", "kid-1")
    assert not v.verify({"n": 5}, None, "kid-1")


def test_verifier_from_hex_public_key():
    signer = Ed25519Signer.generate("kid-1")
    v = Ed25519SignatureVerifier({"kid-1": signer.public_key_hex()})  # hex, not the object
    sig = signer.sign({"n": 5})
    assert v.verify({"n": 5}, sig, "kid-1")


def test_public_verifier_cannot_forge():
    # The verifier holds only the public key; there is no method to produce a
    # valid signature from it. A different signer's signature is rejected.
    signer_a = Ed25519Signer.generate("kid-1")
    signer_b = Ed25519Signer.generate("kid-1")  # different private key, same id
    v = signer_a.verifier()
    assert not v.verify({"n": 5}, signer_b.sign({"n": 5}), "kid-1")


def test_requires_at_least_one_key():
    with pytest.raises(ValueError):
        Ed25519SignatureVerifier({})


def _auth(now, aid="auth-ed"):
    return Authorization(
        customer_id="c", authorization_id=aid, ownership_proof=["dns"],
        targets=["api.example.test"], valid_from=now - timedelta(days=1), valid_until=now + timedelta(days=10),
        permitted_actions=["passive_discovery"], prohibited_actions=["denial_of_service"],
        rate_limits={"requests_per_second": 5, "max_concurrent_sessions": 3},
    )


def test_engine_end_to_end_with_ed25519():
    now = datetime.now(timezone.utc)
    signer = Ed25519Signer.generate("cp-key")
    auth = _auth(now)
    auth.signature = signer.sign(auth.signing_payload())
    auth.signing_key_id = "cp-key"

    engine = PolicyEngine(authorization=auth, verifier=signer.verifier(), audit=lambda _d: None)
    d = engine.authorize(ActionRequest("api.example.test", "passive_discovery"), now=now)
    assert d.verdict == Verdict.ALLOW


def test_engine_rejects_tampered_ed25519_auth():
    now = datetime.now(timezone.utc)
    signer = Ed25519Signer.generate("cp-key")
    auth = _auth(now)
    auth.signature = signer.sign(auth.signing_payload())
    auth.signing_key_id = "cp-key"
    # tamper: widen scope after signing
    auth.targets = ["api.example.test", "evil.example.com"]

    engine = PolicyEngine(authorization=auth, verifier=signer.verifier(), audit=lambda _d: None)
    d = engine.authorize(ActionRequest("evil.example.com", "passive_discovery"), now=now)
    assert d.verdict == Verdict.DENY  # signature no longer valid over the mutated payload


def test_config_prefers_ed25519(tmp_path):
    from aegis.api import ControlPlaneConfig

    signer = Ed25519Signer.generate("cp-key")
    cfg = ControlPlaneConfig(signing_public_keys={"cp-key": signer.public_key_hex()})
    verifier = cfg.build_verifier()
    assert isinstance(verifier, Ed25519SignatureVerifier)
    assert verifier.verify({"n": 1}, signer.sign({"n": 1}), "cp-key")
