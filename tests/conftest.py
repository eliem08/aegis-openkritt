"""Shared fixtures for the policy-core test suite."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from aegis.policy import (
    Authorization,
    HmacSignatureVerifier,
    PolicyConfig,
    PolicyEngine,
)
from policy_helpers import SIGNING_KEY_ID, SIGNING_SECRET, make_authorization, sign


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 8, 2, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def verifier() -> HmacSignatureVerifier:
    return HmacSignatureVerifier({SIGNING_KEY_ID: SIGNING_SECRET})


@pytest.fixture
def valid_auth(now: datetime, verifier: HmacSignatureVerifier) -> Authorization:
    return sign(make_authorization(now), verifier)


@pytest.fixture
def engine(valid_auth: Authorization, verifier: HmacSignatureVerifier) -> PolicyEngine:
    return PolicyEngine(
        authorization=valid_auth,
        verifier=verifier,
        config=PolicyConfig(require_signature=True),
        audit=lambda _decision: None,  # silence logging in tests
    )
