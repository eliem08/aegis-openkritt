"""Reward-threshold awareness: 'profitable' must mean 'findings that actually pay'."""

from __future__ import annotations

from aegis.hunt.reward import (
    DEFAULT_REWARD_POLICIES,
    RewardPolicy,
    eligibility,
    load_reward_policies,
    meets_floor,
    reward_factor,
)
from aegis.hunt.selector import select_programs


def test_meets_floor():
    p = RewardPolicy("x", min_severity="high")
    assert meets_floor("critical", p) and meets_floor("high", p)
    assert not meets_floor("medium", p) and not meets_floor("low", p)
    assert meets_floor("low", None)                       # no policy -> everything passes


def test_coinbase_medium_finding_flagged_out_of_scope():
    # our cb-mpc RNG finding: Medium, hard-to-exploit -> Coinbase excludes it
    pol = DEFAULT_REWARD_POLICIES["coinbase"]
    verdict = eligibility("medium", hard_to_exploit=True, policy=pol)
    assert "OUT OF SCOPE" in verdict
    # even a high-impact-but-hard finding is excluded here
    assert "OUT OF SCOPE" in eligibility("high", hard_to_exploit=True, policy=pol)
    # an easily-exploitable high one clears it
    assert eligibility("high", hard_to_exploit=False, policy=pol).startswith("eligible")


def test_reward_factor_prefers_low_floor_programs():
    assert reward_factor(RewardPolicy("a", min_severity="low")) > \
           reward_factor(RewardPolicy("b", min_severity="high"))
    # hard-to-exploit exclusion further penalizes
    assert reward_factor(RewardPolicy("c", min_severity="high", excludes_hard_to_exploit=True)) < \
           reward_factor(RewardPolicy("d", min_severity="high"))


def test_overlay_merges_over_defaults(tmp_path):
    f = tmp_path / "rp.json"
    f.write_text('{"acme": {"min_severity": "medium", "notes": "n"}}')
    pols = load_reward_policies(str(f))
    assert pols["acme"].min_severity == "medium"
    assert "coinbase" in pols                              # defaults still present


# --- selector integration ---------------------------------------------------

def _repo(org, sev="critical"):
    return {"attributes": {"asset_type": "SOURCE_CODE",
                           "asset_identifier": f"https://github.com/{org}/r",
                           "eligible_for_submission": True, "eligible_for_bounty": True,
                           "max_severity": sev}}


class FakeH1:
    def __init__(self, scopes):
        self._scopes = scopes
    def list_programs(self):
        return [{"attributes": {"handle": h}} for h in self._scopes]
    def get_program(self, h):
        return {"data": {"attributes": {"handle": h, "policy": ""}}}
    def get_structured_scopes(self, h):
        return self._scopes[h]


def test_selector_deprioritizes_high_floor_program():
    # two equally-critical-ceiling programs; one pays only for critical, one for low
    h1 = FakeH1({"payslow": [_repo("payslow")], "payshigh": [_repo("payshigh")]})
    pols = {"payshigh": RewardPolicy("payshigh", min_severity="critical", excludes_hard_to_exploit=True)}
    ranked = select_programs(h1, want=2, reward_policies=pols)
    assert ranked[0].handle == "payslow"                  # low-floor program ranks first
    assert ranked[1].reward_floor == "critical"


def test_selector_drops_program_whose_ceiling_cannot_reach_floor():
    # scope max_severity is 'low' but the program only pays 'high' -> can never pay
    h1 = FakeH1({"hopeless": [_repo("hopeless", sev="low")]})
    pols = {"hopeless": RewardPolicy("hopeless", min_severity="high")}
    assert select_programs(h1, want=5, reward_policies=pols) == []
