"""The policy arsenal is enforced by the Jarvis PolicyGate (metadata-driven, non-breaking)."""

from __future__ import annotations

import pytest

from aegis.ai.agentic_os import AgentRole, RiskClass
from aegis.ai.jarvis.guards import PolicyGate
from aegis.ai.jarvis.models import ActionProposal, HuntObjective

SD = "scope-digest-1"
OBJ = HuntObjective(
    program_id="acme", target="app.example.com", scope_digest=SD,
    maximum_cost_usd=100.0, maximum_requests=100,
)
ELIGIBLE = {
    "handle": "acme", "active": True, "reward_ceiling": 5000.0,
    "bounty_eligible_targets": ["app.example.com"], "targets": ["app.example.com"],
    "out_of_scope": [], "scope_text": "In scope: app.example.com",
}


def _proposal(metadata, *, risk=RiskClass.READ_ONLY, network=False):
    return ActionProposal(
        agent=list(AgentRole)[0], action="probe", reason="test", scope_digest=SD,
        risk=risk, estimated_cost_usd=0.0, estimated_requests=0,
        requires_network=network, metadata=metadata,
    )


def _deny_reasons(metadata, **kw):
    d = PolicyGate().evaluate(OBJ, _proposal(metadata), **kw)
    return d.allowed, set(d.reasons)


def test_dos_vrt_category_blocked():
    allowed, reasons = _deny_reasons({"vrt_category": "Application-Level Denial-of-Service (DoS)"})
    assert not allowed
    assert any(r.startswith("vrt_lane_blocked") for r in reasons)


def test_out_of_boundary_vrt_blocked():
    allowed, reasons = _deny_reasons({"vrt_category": "Automotive Security Misconfiguration"})
    assert not allowed
    assert "vrt_lane_blocked:out_of_boundary" in reasons


def test_prohibited_action_class_blocked():
    allowed, reasons = _deny_reasons({"action_class": "captcha_bypass"})
    assert not allowed
    assert "prohibited_action_class:captcha_bypass" in reasons


def test_consequential_action_needs_human_approval():
    allowed, reasons = _deny_reasons({"action_class": "rce"})
    assert not allowed
    assert "human_approval_required" in reasons


def test_ineligible_target_blocked():
    prog = dict(ELIGIBLE, out_of_scope=["app.example.com"])
    allowed, reasons = _deny_reasons({"program": prog})
    assert not allowed
    assert any(r.startswith("target_not_eligible") for r in reasons)


def test_clean_readonly_proposal_allowed():
    allowed, reasons = _deny_reasons(
        {"vrt_category": "Broken Access Control (BAC)", "action_class": "read", "program": ELIGIBLE}
    )
    assert allowed, reasons


def test_backward_compatible_no_metadata_allowed():
    # No policy metadata → new checks skip entirely; a clean read-only proposal still passes.
    allowed, _ = _deny_reasons({})
    assert allowed


def test_consequential_allowed_with_human_approval():
    allowed, reasons = _deny_reasons({"action_class": "rce", "program": ELIGIBLE}, human_approved=True)
    assert allowed, reasons
