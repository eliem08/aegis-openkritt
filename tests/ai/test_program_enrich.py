"""Program enrichment — reward from disclosed payouts, crowding, priors, GitHub age."""

from __future__ import annotations

from aegis.ai.program_enrich import (
    apply_reward_priors,
    enrich_age_from_github,
    enrich_from_disclosed,
)
from aegis.ai.registry import Program


def _bc(handle, reward=0, paid=0):
    return Program(handle=handle, platform="bugcrowd", targets=["a/b"],
                   reward_ceiling=reward, paid_reports=paid)


_DISCLOSED = [
    {"platform": "bugcrowd", "program_url": "https://bugcrowd.com/engagements/acme",
     "amount": 5000, "amount_estimated": False},
    {"platform": "bugcrowd", "program_url": "https://bugcrowd.com/engagements/acme",
     "amount": 1200, "amount_estimated": False},
    {"platform": "bugcrowd", "program_url": "https://bugcrowd.com/engagements/acme",
     "amount": 9999, "amount_estimated": True},           # estimate — ignored for reward
]


def test_reward_from_disclosed_uses_max_real_amount():
    progs = [_bc("bugcrowd-acme")]
    enrich_from_disclosed(progs, _DISCLOSED)
    assert progs[0].reward_ceiling == 5000                # max real, estimate ignored
    assert progs[0].paid_reports == 3                     # crowding = all disclosed rows


def test_reward_from_disclosed_does_not_lower_existing():
    progs = [_bc("bugcrowd-acme", reward=8000)]
    enrich_from_disclosed(progs, _DISCLOSED)
    assert progs[0].reward_ceiling == 8000                # keeps the higher existing value


def test_no_match_leaves_program_untouched():
    progs = [_bc("bugcrowd-other")]
    enrich_from_disclosed(progs, _DISCLOSED)
    assert progs[0].reward_ceiling == 0 and progs[0].paid_reports == 0


def test_reward_priors_fill_zero_and_label():
    progs = [Program(handle="h1prog", platform="hackerone", reward_ceiling=0),
             Program(handle="bcprog", platform="bugcrowd", reward_ceiling=3000)]
    apply_reward_priors(progs)
    assert progs[0].reward_ceiling == 2500 and "[reward=prior]" in progs[0].notes
    assert progs[1].reward_ceiling == 3000 and "prior" not in progs[1].notes  # real kept


def test_github_age_fills_missing_only():
    progs = [Program(handle="p", platform="hackerone", targets=["owner/repo"])]

    def fake(url, headers):
        return {"created_at": "2020-01-01T00:00:00Z"}     # ~old repo
    n = enrich_age_from_github(progs, fetch_json=fake)
    assert n == 1 and progs[0].age_months > 40


def test_github_age_degrades_on_error():
    progs = [Program(handle="p", platform="hackerone", targets=["owner/repo"])]

    def bad(url, headers):
        raise RuntimeError("rate limited")
    assert enrich_age_from_github(progs, fetch_json=bad) == 0
    assert progs[0].age_months == 0                       # untouched, no crash
