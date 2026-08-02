"""End-to-end policy-engine tests: every gate, fail-closed behaviour, and audit."""

from __future__ import annotations

import json

import pytest

from aegis.policy import (
    ActionRequest,
    ConsequenceTier,
    KillSwitch,
    PolicyConfig,
    PolicyEngine,
    RateBudget,
    ReasonCode,
    Verdict,
    approval_token_for_tier,
)
from policy_helpers import make_authorization, sign


def codes(decision) -> set[ReasonCode]:
    return {r.code for r in decision.reasons}


# --- happy path -----------------------------------------------------------

def test_passive_action_in_scope_is_allowed(engine, now):
    req = ActionRequest(target="api.example.test", action="passive_discovery")
    d = engine.authorize(req, now=now)
    assert d.verdict == Verdict.ALLOW
    assert d.allowed
    assert d.tier == ConsequenceTier.PASSIVE
    assert d.incidents == []
    assert d.authorization_id == "auth-2026-001"


def test_non_invasive_active_allowed_within_budget(engine, now):
    req = ActionRequest(target="app.example.test", action="authenticated_testing")
    d = engine.authorize(req, now=now)
    assert d.verdict == Verdict.ALLOW
    assert d.tier == ConsequenceTier.NON_INVASIVE_ACTIVE


# --- scope ----------------------------------------------------------------

def test_out_of_scope_denied_with_scope_escape_incident(engine, now):
    req = ActionRequest(target="evil.example.com", action="passive_discovery")
    d = engine.authorize(req, now=now)
    assert d.verdict == Verdict.DENY
    assert ReasonCode.TARGET_OUT_OF_SCOPE in codes(d)
    assert "SCOPE_ESCAPE" in d.incidents


def test_target_in_allowlist_but_not_auth_targets_denied(now, verifier):
    # Network allowlist knows the host, but the authorization does not cover it.
    auth = sign(make_authorization(now, targets=["api.example.test"]), verifier)
    from aegis.policy import ScopeGuard

    engine = PolicyEngine(
        authorization=auth,
        verifier=verifier,
        scope=ScopeGuard(["api.example.test", "app.example.test"]),
        audit=lambda _d: None,
    )
    d = engine.authorize(ActionRequest(target="app.example.test", action="passive_discovery"), now=now)
    assert d.verdict == Verdict.DENY
    assert ReasonCode.TARGET_OUT_OF_SCOPE in codes(d)


# --- prohibition / permission --------------------------------------------

def test_prohibited_action_denied(engine, now):
    req = ActionRequest(target="api.example.test", action="denial_of_service")
    d = engine.authorize(req, now=now)
    assert d.verdict == Verdict.DENY
    assert ReasonCode.ACTION_PROHIBITED in codes(d)
    assert "PROHIBITED_ACTION_BLOCKED" in d.incidents


def test_action_not_in_permitted_list_denied(engine, now):
    req = ActionRequest(target="api.example.test", action="spec_ingestion")  # passive but not permitted
    d = engine.authorize(req, now=now)
    assert d.verdict == Verdict.DENY
    assert ReasonCode.ACTION_NOT_PERMITTED in codes(d)


# --- approvals ------------------------------------------------------------

def test_sensitive_action_requires_approval_then_allows(engine, now):
    req = ActionRequest(target="api.example.test", action="cross_tenant_proof")
    d = engine.authorize(req, now=now)
    assert d.verdict == Verdict.REQUIRE_APPROVAL
    # needs both the per-action token and the tier token
    assert set(d.required_approvals) == {"cross_tenant_proof", approval_token_for_tier(ConsequenceTier.SENSITIVE)}

    approved = ActionRequest(
        target="api.example.test",
        action="cross_tenant_proof",
        approvals=frozenset(d.required_approvals),
    )
    d2 = engine.authorize(approved, now=now)
    assert d2.verdict == Verdict.ALLOW


def test_partial_approval_still_requires_remaining(engine, now):
    req = ActionRequest(
        target="api.example.test",
        action="cross_tenant_proof",
        approvals=frozenset({"cross_tenant_proof"}),  # missing the tier token
    )
    d = engine.authorize(req, now=now)
    assert d.verdict == Verdict.REQUIRE_APPROVAL
    assert d.required_approvals == [approval_token_for_tier(ConsequenceTier.SENSITIVE)]


def test_state_changing_requires_approval_by_default(engine, now):
    req = ActionRequest(target="api.example.test", action="safe_state_change")
    d = engine.authorize(req, now=now)
    assert d.verdict == Verdict.REQUIRE_APPROVAL
    assert d.required_approvals == [approval_token_for_tier(ConsequenceTier.STATE_CHANGING)]


def test_state_changing_auto_approved_when_configured(valid_auth, verifier, now):
    engine = PolicyEngine(
        authorization=valid_auth,
        verifier=verifier,
        config=PolicyConfig(auto_approve_tiers=frozenset({ConsequenceTier.STATE_CHANGING})),
        audit=lambda _d: None,
    )
    d = engine.authorize(ActionRequest(target="api.example.test", action="safe_state_change"), now=now)
    assert d.verdict == Verdict.ALLOW


def test_config_cannot_auto_approve_sensitive():
    with pytest.raises(ValueError):
        PolicyConfig(auto_approve_tiers=frozenset({ConsequenceTier.SENSITIVE}))


def test_unknown_but_permitted_action_requires_approval(engine, now):
    req = ActionRequest(target="api.example.test", action="custom_probe")
    d = engine.authorize(req, now=now)
    assert d.verdict == Verdict.REQUIRE_APPROVAL
    assert ReasonCode.UNKNOWN_ACTION in codes(d)
    assert d.tier == ConsequenceTier.SENSITIVE


# --- kill switch ----------------------------------------------------------

def test_kill_switch_denies_everything(valid_auth, verifier, now):
    ks = KillSwitch()
    ks.fire("latency spike")
    engine = PolicyEngine(authorization=valid_auth, verifier=verifier, kill_switch=ks, audit=lambda _d: None)
    d = engine.authorize(ActionRequest(target="api.example.test", action="passive_discovery"), now=now)
    assert d.verdict == Verdict.DENY
    assert ReasonCode.KILL_SWITCH_ACTIVE in codes(d)
    assert "KILL_SWITCH" in d.incidents


# --- authorization validity ----------------------------------------------

def test_missing_authorization_escalates(verifier, now):
    engine = PolicyEngine(authorization=None, verifier=verifier, audit=lambda _d: None)
    d = engine.authorize(ActionRequest(target="api.example.test", action="passive_discovery"), now=now)
    assert d.verdict == Verdict.ESCALATE
    assert ReasonCode.NO_AUTHORIZATION in codes(d)


def test_expired_authorization_escalates(now, verifier):
    from datetime import timedelta

    auth = sign(
        make_authorization(now, valid_from=now - timedelta(days=5), valid_until=now - timedelta(days=1)),
        verifier,
    )
    engine = PolicyEngine(authorization=auth, verifier=verifier, audit=lambda _d: None)
    d = engine.authorize(ActionRequest(target="api.example.test", action="passive_discovery"), now=now)
    assert d.verdict == Verdict.ESCALATE
    assert ReasonCode.AUTHORIZATION_EXPIRED in codes(d)


def test_tampered_signature_denies(engine_free_auth):
    engine, req, now = engine_free_auth
    d = engine.authorize(req, now=now)
    assert d.verdict == Verdict.DENY
    assert ReasonCode.SIGNATURE_INVALID in codes(d)


@pytest.fixture
def engine_free_auth(now, verifier):
    auth = sign(make_authorization(now), verifier)
    auth.signature = "00" * 32  # corrupt
    engine = PolicyEngine(authorization=auth, verifier=verifier, audit=lambda _d: None)
    req = ActionRequest(target="api.example.test", action="passive_discovery")
    return engine, req, now


# --- environment ----------------------------------------------------------

def test_production_touch_on_staging_escalates(engine, now):
    req = ActionRequest(target="api.example.test", action="authenticated_testing", touches_production=True)
    d = engine.authorize(req, now=now)
    assert d.verdict == Verdict.ESCALATE
    assert ReasonCode.ENVIRONMENT_MISMATCH in codes(d)


# --- budgets --------------------------------------------------------------

def test_rate_budget_exhausted_after_commits(valid_auth, verifier, now):
    engine = PolicyEngine(
        authorization=valid_auth,
        verifier=verifier,
        rate_budget=RateBudget(requests_per_second=1, max_concurrent_sessions=3),
        audit=lambda _d: None,
    )
    req = ActionRequest(target="api.example.test", action="passive_discovery")
    d1 = engine.authorize(req, now=now)
    assert d1.allowed
    engine.commit(d1, now=now)  # drain the single token
    d2 = engine.authorize(req, now=now)
    assert d2.verdict == Verdict.DENY
    assert ReasonCode.RATE_BUDGET_EXCEEDED in codes(d2)


def test_concurrency_exhausted(engine, now):
    for _ in range(3):
        assert engine.rate_budget.acquire_session()
    req = ActionRequest(target="api.example.test", action="passive_discovery")
    d = engine.authorize(req, now=now)
    assert d.verdict == Verdict.DENY
    assert ReasonCode.CONCURRENCY_EXCEEDED in codes(d)


def test_spend_budget_exceeded(engine, now):
    req = ActionRequest(target="api.example.test", action="passive_discovery", estimated_cost=150.0)
    d = engine.authorize(req, now=now)
    assert d.verdict == Verdict.DENY
    assert ReasonCode.SPEND_BUDGET_EXCEEDED in codes(d)


def test_authorize_is_non_mutating_on_budget(engine, now):
    req = ActionRequest(target="api.example.test", action="passive_discovery")
    for _ in range(10):
        assert engine.authorize(req, now=now).allowed  # never commits, never drains


def test_commit_records_spend(engine, now):
    req = ActionRequest(target="api.example.test", action="passive_discovery", estimated_cost=40.0)
    d = engine.authorize(req, now=now)
    engine.commit(d, request=req, now=now)
    assert engine.spend_budget.spent == 40.0


def test_cannot_commit_denied_decision(engine, now):
    d = engine.authorize(ActionRequest(target="evil.com", action="passive_discovery"), now=now)
    with pytest.raises(ValueError):
        engine.commit(d, now=now)


# --- audit ----------------------------------------------------------------

def test_decision_is_json_serialisable(engine, now):
    d = engine.authorize(ActionRequest(target="api.example.test", action="passive_discovery"), now=now)
    payload = json.dumps(d.as_dict())
    assert "verdict" in payload


def test_audit_sink_is_called(valid_auth, verifier, now):
    seen = []
    engine = PolicyEngine(authorization=valid_auth, verifier=verifier, audit=seen.append)
    engine.authorize(ActionRequest(target="api.example.test", action="passive_discovery"), now=now)
    assert len(seen) == 1
