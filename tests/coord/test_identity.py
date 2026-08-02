"""Signed worker identities + typed capability queues (Phase 5)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aegis.coord import (
    InvalidWorkerIdentity,
    WorkerAuthority,
    WorkerIdentityExpired,
    WorkerIdentityIssuer,
    worker_proof,
)
from aegis.policy.signing import HmacSignatureVerifier

ISSUER_KID = "control-plane"
issuer_verifier = HmacSignatureVerifier({ISSUER_KID: "issuer-secret"})
worker_verifier = HmacSignatureVerifier({"wk-browser": "browser-secret", "wk-bad": "attacker-secret"})


class Clock:
    def __init__(self):
        self.now = datetime(2026, 8, 2, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, s):
        self.now += timedelta(seconds=s)


def issuer():
    return WorkerIdentityIssuer(issuer_verifier, key_id=ISSUER_KID)


def authority(clock=None):
    return WorkerAuthority(issuer_verifier, worker_verifier=worker_verifier, clock=clock)


def browser_identity(clock=None, ttl=900):
    now = clock.now if clock else None
    return issuer().issue("worker-1", capabilities=("browser", "discovery"),
                          worker_key_id="wk-browser", ttl_seconds=ttl, now=now)


# --- issuance + verification -------------------------------------------------

def test_issued_identity_verifies():
    authority().verify(browser_identity())     # no raise


def test_tampered_capabilities_fail_verification():
    identity = browser_identity()
    forged = type(identity)(**{**vars(identity), "capabilities": ("browser", "template")})
    with pytest.raises(InvalidWorkerIdentity):
        authority().verify(forged)


def test_unsigned_identity_is_rejected():
    identity = browser_identity()
    unsigned = type(identity)(**{**vars(identity), "signature": None})
    with pytest.raises(InvalidWorkerIdentity):
        authority().verify(unsigned)


def test_expired_identity_is_rejected():
    clock = Clock()
    identity = browser_identity(clock, ttl=100)
    clock.advance(200)
    with pytest.raises(WorkerIdentityExpired):
        authority(clock).verify(identity)


# --- typed capability queues -------------------------------------------------

def test_worker_claims_only_its_declared_queues():
    auth = authority()
    identity = browser_identity()
    assert auth.can_claim(identity, "browser") and auth.can_claim(identity, "discovery")
    # a browser worker cannot take OAST or template-scan work
    assert not auth.can_claim(identity, "oast")
    assert not auth.can_claim(identity, "template")
    assert not auth.can_claim(identity, "active")


def test_expired_identity_cannot_claim_anything():
    clock = Clock()
    identity = browser_identity(clock, ttl=100)
    clock.advance(200)
    assert authority(clock).can_claim(identity, "browser") is False


# --- mutual authentication ---------------------------------------------------

def test_mutual_authentication_requires_a_valid_worker_proof():
    auth = authority()
    identity = browser_identity()
    proof = worker_proof(worker_verifier, worker_id="worker-1", worker_key_id="wk-browser", nonce="n1")
    assert auth.authenticate(identity, nonce="n1", worker_proof=proof) is True


def test_wrong_worker_key_fails_mutual_auth():
    auth = authority()
    identity = browser_identity()
    # attacker signs with a different worker key than the identity names
    bad = worker_proof(worker_verifier, worker_id="worker-1", worker_key_id="wk-bad", nonce="n1")
    assert auth.authenticate(identity, nonce="n1", worker_proof=bad) is False


def test_replayed_nonce_mismatch_fails_mutual_auth():
    auth = authority()
    identity = browser_identity()
    proof = worker_proof(worker_verifier, worker_id="worker-1", worker_key_id="wk-browser", nonce="n1")
    assert auth.authenticate(identity, nonce="different-nonce", worker_proof=proof) is False


def test_forged_issuer_signature_fails_authentication():
    # an identity 'issued' by an attacker who doesn't hold the control-plane key
    rogue = WorkerIdentityIssuer(HmacSignatureVerifier({ISSUER_KID: "wrong-secret"}), key_id=ISSUER_KID)
    identity = rogue.issue("worker-x", capabilities=("template", "oast"), worker_key_id="wk-browser")
    assert authority().can_claim(identity, "template") is False
