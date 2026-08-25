"""Tests for the governed live-action gate (composition of all authorities)."""

from __future__ import annotations

from dataclasses import dataclass

from aegis.policy.live_gate import LiveVerdict, evaluate_live_action
from aegis.policy.program_eligibility import Eligibility


# --- duck-typed kernel fakes -------------------------------------------------

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
    "handle": "acme-bbp", "active": True, "reward_ceiling": 5000.0,
    "bounty_eligible_targets": ["app.example.com"], "targets": ["app.example.com"],
    "out_of_scope": [], "scope_text": "In scope: app.example.com",
}
SCOPE = ["app.example.com"]


def _call(action_class, *, program=ELIGIBLE_PROG, scope=SCOPE, policy=None,
          receipt=None, finding_id=None, target="https://app.example.com/x"):
    return evaluate_live_action(
        program=program, target=target, action_class=action_class,
        proposal=object(), authorization=object(),
        policy=policy or FakePolicy(approve=True),
        scope_targets=scope, approval_receipt=receipt, finding_id=finding_id,
    )


def test_prohibited_class_denied_even_when_all_else_valid():
    d = _call("dos")
    assert d.verdict is LiveVerdict.DENY
    assert "prohibited" in " ".join(d.reasons)


def test_ineligible_target_denied():
    prog = dict(ELIGIBLE_PROG, out_of_scope=["app.example.com"])
    d = _call("read", program=prog)
    assert d.verdict is LiveVerdict.DENY
    assert d.eligibility is Eligibility.NOT_ELIGIBLE


def test_out_of_signed_scope_denied():
    d = _call("read", scope=["other.example.com"])  # eligible program, but not in signed allowlist
    assert d.verdict is LiveVerdict.DENY
    assert "signed scope" in " ".join(d.reasons)


def test_no_grant_denied_by_kernel_policy():
    d = _call("read", policy=FakePolicy(approve=False, reason="network needs execution grant"))
    assert d.verdict is LiveVerdict.DENY
    assert "kernel policy denied" in " ".join(d.reasons)


def test_nonconsequential_allowed_when_everything_valid():
    d = _call("read")
    assert d.verdict is LiveVerdict.ALLOW
    assert d.allowed


def test_consequential_without_approval_escalates():
    d = _call("rce")
    assert d.verdict is LiveVerdict.ESCALATE
    assert "HumanApprovalReceipt" in " ".join(d.reasons)


def test_consequential_with_valid_approval_allowed():
    d = _call("rce", receipt=FakeReceipt(valid=True), finding_id="f1")
    assert d.verdict is LiveVerdict.ALLOW


def test_consequential_with_invalid_approval_escalates():
    d = _call("rce", receipt=FakeReceipt(valid=False), finding_id="f1")
    assert d.verdict is LiveVerdict.ESCALATE


def test_policy_exception_fails_closed():
    class Boom:
        def evaluate(self, proposal, authorization):
            raise RuntimeError("kernel exploded")
    d = _call("read", policy=Boom())
    assert d.verdict is LiveVerdict.DENY
    assert "fail-closed" in " ".join(d.reasons)
