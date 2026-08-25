"""Tests for fresh-target discovery ranking + gate integration."""

from __future__ import annotations

from aegis.policy.program_discovery import discover
from aegis.policy.program_eligibility import Eligibility

FRESH = {
    "handle": "fresh-startup", "platform": "hackerone", "active": True,
    "reward_ceiling": 10000.0,
    "bounty_eligible_targets": ["neworg/coolapp"], "targets": ["neworg/coolapp"],
    "out_of_scope": [], "scope_text": "In scope: neworg/coolapp",
    "saturation": 0.1, "paid_reports": 3, "age_months": 2,
}
ELITE = {
    "handle": "elite-giant", "platform": "hackerone", "active": True,
    "reward_ceiling": 35000.0,
    "bounty_eligible_targets": ["bigorg/hugelib"], "targets": ["bigorg/hugelib"],
    "out_of_scope": [], "scope_text": "In scope: bigorg/hugelib",
    "saturation": 0.95, "paid_reports": 800, "age_months": 130,
}
SUSPENDED = {
    "handle": "suspended-co", "platform": "hackerone", "active": True,
    "reward_ceiling": 5000.0,
    "bounty_eligible_targets": ["org/app"], "targets": ["org/app"], "out_of_scope": [],
    "scope_text": "No monetary bounties. We have suspended our paid bounty program.",
    "saturation": 0.2, "paid_reports": 1, "age_months": 5,
}
DESCOPED = {
    "handle": "wise", "platform": "bugcrowd", "active": True, "reward_ceiling": 4000.0,
    "targets": ["transferwise/pipelinewise"], "bounty_eligible_targets": [],
    "out_of_scope": ["github.com/transferwise/pipelinewise"],
    "scope_text": "github.com/transferwise/* (Recon).",
    "saturation": 0.5, "paid_reports": 200,
}


def test_less_hunted_ranks_above_elite():
    q = discover([ELITE, FRESH])
    assert [c.target for c in q] == ["neworg/coolapp", "bigorg/hugelib"]
    assert q[0].score > q[1].score  # fresher wins despite lower ceiling


def test_all_cash_candidates_are_submittable_and_paying():
    for c in discover([FRESH, ELITE]):
        assert c.verdict is Eligibility.SUBMITTABLE
        assert c.pays_cash
        assert c.needs_live_verify  # snapshot data must be live-verified


def test_descoped_target_never_surfaces():
    q = discover([DESCOPED, FRESH])
    assert all(c.target != "transferwise/pipelinewise" for c in q)


def test_require_cash_drops_suspended():
    assert discover([SUSPENDED]) == []  # CREDIT_ONLY, no cash → dropped by default


def test_credit_run_includes_suspended():
    q = discover([SUSPENDED],
                 include=(Eligibility.SUBMITTABLE, Eligibility.CREDIT_ONLY),
                 require_cash=False)
    assert len(q) == 1
    assert q[0].verdict is Eligibility.CREDIT_ONLY
    assert q[0].pays_cash is False


def test_limit_caps_queue():
    assert len(discover([FRESH, ELITE], limit=1)) == 1
