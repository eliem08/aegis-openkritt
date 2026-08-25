"""Tests for the governed live lane (planner over the live_gate; no network I/O)."""

from __future__ import annotations

from dataclasses import dataclass

from aegis.policy.live_gate import LiveVerdict
from aegis.policy.live_lane import (
    READ_ONLY_ACTION_CLASS,
    action_class_for,
    plan_live_check,
)


# --- duck-typed kernel fakes (mirror test_live_gate) -------------------------

@dataclass
class FakeDecision:
    approved: bool
    reason: str = ""


class FakePolicy:
    def __init__(self, approve: bool = True, reason: str = "authorized"):
        self._approve, self._reason = approve, reason

    def evaluate(self, proposal, authorization):
        return FakeDecision(self._approve, self._reason)


class FakeReceipt:
    def __init__(self, valid: bool = True):
        self._valid = valid

    def verify(self, verifier, finding_id, key_id="approval"):
        return self._valid


ELIGIBLE_PROG = {
    "handle": "acme-bbp", "active": True, "reward_ceiling": 9000.0,
    "bounty_eligible_targets": ["app.example.com"], "targets": ["app.example.com"],
    "out_of_scope": [], "scope_text": "In scope: app.example.com",
}
SCOPE = ["app.example.com"]


def _plan(category, specific, *, scope=SCOPE, policy=None, receipt=None,
          finding_id=None, action_class=None, target="https://app.example.com/x"):
    return plan_live_check(
        program=ELIGIBLE_PROG, target=target, vrt_category=category,
        vrt_specific=specific, check_description="non-destructive read of the live response",
        proposal=object(), authorization=object(), policy=policy or FakePolicy(approve=True),
        scope_targets=scope, action_class=action_class,
        approval_receipt=receipt, finding_id=finding_id,
    )


def test_action_class_readonly_vs_consequential():
    assert action_class_for("Server Security Misconfiguration", "Lack of Security Headers") == READ_ONLY_ACTION_CLASS
    assert action_class_for("Server Security Misconfiguration", "Cache Poisoning") == "state_change"
    assert action_class_for("Server Security Misconfiguration", "Misconfigured DNS Subdomain Takeover") == "account_takeover"


def test_non_live_class_is_skipped():
    r = _plan("Broken Access Control (BAC)", "Insecure Direct Object References (IDOR)")
    assert not r.pursued
    assert r.skipped_reason and "not live_only" in r.skipped_reason


def test_readonly_live_check_allowed_when_everything_valid():
    r = _plan("Server Security Misconfiguration", "Lack of Security Headers")
    assert r.pursued and r.action_class == READ_ONLY_ACTION_CLASS
    assert r.verdict is LiveVerdict.ALLOW and r.allowed
    assert r.approval_packet is None


def test_consequential_live_check_escalates_with_packet():
    r = _plan("Server Security Misconfiguration", "Cache Poisoning")
    assert r.pursued and r.needs_human
    assert r.verdict is LiveVerdict.ESCALATE
    assert r.approval_packet is not None
    assert r.approval_packet["check"]  # the exact check is carried for the operator
    assert r.approval_packet["consequential"] is True


def test_consequential_live_check_allowed_with_valid_receipt():
    r = _plan("Server Security Misconfiguration", "Cache Poisoning",
              receipt=FakeReceipt(valid=True), finding_id="f1")
    assert r.verdict is LiveVerdict.ALLOW and r.approval_packet is None


def test_prohibited_action_denied_even_on_live_class():
    r = _plan("Server Security Misconfiguration", "Lack of Security Headers", action_class="dos")
    assert r.verdict is LiveVerdict.DENY


def test_out_of_signed_scope_denied():
    r = _plan("Server Security Misconfiguration", "Lack of Security Headers", scope=["other.example.com"])
    assert r.verdict is LiveVerdict.DENY
    assert "signed scope" in " ".join(r.decision.reasons)


def test_ai_model_extraction_routes_to_live_and_escalates():
    r = _plan("AI Application Security", "Model Extraction")
    assert r.pursued and r.needs_human  # live model probing is consequential -> approval needed
