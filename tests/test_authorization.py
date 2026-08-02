from datetime import timedelta

import pytest
from pydantic import ValidationError

from aegis.policy import Authorization, AuthorizationValidator, ReasonCode, Verdict
from policy_helpers import make_authorization, sign


def test_rejects_extra_fields(now):
    with pytest.raises(ValidationError):
        make_authorization(now, surprise_field="nope")


def test_rejects_inverted_window(now):
    with pytest.raises(ValidationError):
        make_authorization(now, valid_from=now, valid_until=now - timedelta(days=1))


def test_naive_datetimes_coerced_to_utc(now):
    auth = make_authorization(now)
    assert auth.valid_from.tzinfo is not None
    assert auth.valid_until.tzinfo is not None


def test_predicates(now):
    auth = make_authorization(now)
    assert auth.permits("passive_discovery")
    assert not auth.permits("nope")
    assert auth.prohibits("denial_of_service")
    assert auth.requires_approval("cross_tenant_proof")
    assert auth.covers_target("api.example.test")
    assert not auth.covers_target("evil.test")
    assert auth.is_time_valid(now)
    assert not auth.is_time_valid(now + timedelta(days=365))


def test_covers_target_supports_wildcards(now):
    auth = make_authorization(now, targets=["*.example.test", "api.example.test"])
    assert auth.covers_target("anything.example.test")  # wildcard subdomain
    assert auth.covers_target("api.example.test")  # exact
    assert not auth.covers_target("example.test")  # apex not covered by *.example.test
    assert not auth.covers_target("evil.com")


def test_validator_accepts_valid_signed_auth(now, verifier):
    auth = sign(make_authorization(now), verifier)
    v = AuthorizationValidator(verifier=verifier, require_signature=True)
    assert v.validate(auth, now) == []


def test_validator_none_auth_escalates(now, verifier):
    v = AuthorizationValidator(verifier=verifier)
    reasons = v.validate(None, now)
    assert reasons[0].code == ReasonCode.NO_AUTHORIZATION
    assert reasons[0].verdict == Verdict.ESCALATE


def test_validator_flags_expired(now, verifier):
    auth = sign(
        make_authorization(now, valid_from=now - timedelta(days=10), valid_until=now - timedelta(days=1)),
        verifier,
    )
    v = AuthorizationValidator(verifier=verifier)
    codes = {r.code for r in v.validate(auth, now)}
    assert ReasonCode.AUTHORIZATION_EXPIRED in codes


def test_validator_flags_not_yet_valid(now, verifier):
    auth = sign(
        make_authorization(now, valid_from=now + timedelta(days=1), valid_until=now + timedelta(days=10)),
        verifier,
    )
    v = AuthorizationValidator(verifier=verifier)
    codes = {r.code for r in v.validate(auth, now)}
    assert ReasonCode.AUTHORIZATION_NOT_YET_VALID in codes


def test_validator_flags_missing_ownership_proof(now, verifier):
    auth = sign(make_authorization(now, ownership_proof=[]), verifier)
    v = AuthorizationValidator(verifier=verifier)
    codes = {r.code for r in v.validate(auth, now)}
    assert ReasonCode.OWNERSHIP_PROOF_MISSING in codes


def test_validator_unsigned_when_required_escalates(now, verifier):
    auth = make_authorization(now)  # not signed
    v = AuthorizationValidator(verifier=verifier, require_signature=True)
    codes = {r.code for r in v.validate(auth, now)}
    assert ReasonCode.SIGNATURE_MISSING in codes


def test_validator_bad_signature_denies(now, verifier):
    auth = sign(make_authorization(now), verifier)
    auth.signature = "deadbeef" * 8  # corrupt it
    v = AuthorizationValidator(verifier=verifier, require_signature=True)
    reasons = v.validate(auth, now)
    codes = {r.code for r in reasons}
    assert ReasonCode.SIGNATURE_INVALID in codes
    bad = next(r for r in reasons if r.code == ReasonCode.SIGNATURE_INVALID)
    assert bad.verdict == Verdict.DENY


def test_validator_can_skip_signature(now):
    auth = make_authorization(now)
    v = AuthorizationValidator(verifier=None, require_signature=False)
    assert v.validate(auth, now) == []
