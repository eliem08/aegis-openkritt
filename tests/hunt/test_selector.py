"""Automatic, profit-aware program selection — no handle, and it can't pick a dud."""

from __future__ import annotations

from aegis.hunt.selector import select_programs


def repo(org, *, bounty=True, severity="high", i=0):
    return {"attributes": {"asset_type": "SOURCE_CODE",
                           "asset_identifier": f"https://github.com/{org}/repo{i}",
                           "eligible_for_submission": True,
                           "eligible_for_bounty": bounty, "max_severity": severity}}


WEB = {"attributes": {"asset_type": "URL", "asset_identifier": "https://app.x.com",
                      "eligible_for_submission": True, "eligible_for_bounty": True}}


class FakeH1:
    def __init__(self, programs, scopes, attrs=None):
        self._programs = programs
        self._scopes = scopes
        self._attrs = attrs or {}

    def list_programs(self):
        return self._programs

    def get_program(self, handle):
        a = {"handle": handle, "policy": ""}
        a.update(self._attrs.get(handle, {}))
        return {"data": {"attributes": a}}

    def get_structured_scopes(self, handle):
        return self._scopes.get(handle, [])


def _progs(*handles):
    return [{"attributes": {"handle": h}} for h in handles]


def test_selects_only_programs_with_code_repos():
    h1 = FakeH1(_progs("has-code", "web-only"),
                {"has-code": [repo("has-code")], "web-only": [WEB]})
    assert [c.handle for c in select_programs(h1, want=5)] == ["has-code"]


def test_never_selects_an_automation_forbidden_program():
    h1 = FakeH1(_progs("noauto"), {"noauto": [repo("noauto")]},
                attrs={"noauto": {"policy": "Automated tools and automated scanning are prohibited."}})
    assert select_programs(h1, want=5) == []


def test_require_bounty_drops_vdp_only_programs():
    h1 = FakeH1(_progs("vdp"), {"vdp": [repo("vdp", bounty=False)]})
    assert select_programs(h1, want=5, require_bounty=True) == []      # no payout -> not selected
    assert [c.handle for c in select_programs(h1, want=5, require_bounty=False)] == ["vdp"]


def test_ranks_by_profitability_severity_ceiling_first():
    h1 = FakeH1(_progs("low-pay", "high-pay"),
                {"low-pay": [repo("low-pay", severity="low")],
                 "high-pay": [repo("high-pay", severity="critical")]})
    picked = select_programs(h1, want=2)
    assert picked[0].handle == "high-pay" and picked[0].top_severity == "critical"
    assert picked[0].profitability > picked[1].profitability


def test_more_bounty_repos_raises_profitability():
    h1 = FakeH1(_progs("one", "many"),
                {"one": [repo("one", severity="high")],
                 "many": [repo("many", severity="high", i=1), repo("many", severity="high", i=2)]})
    assert select_programs(h1, want=2)[0].handle == "many"


def test_want_caps_the_selection():
    handles = [f"p{i}" for i in range(6)]
    h1 = FakeH1(_progs(*handles), {h: [repo(h)] for h in handles})
    assert len(select_programs(h1, want=3)) == 3


def test_inspect_limit_bounds_the_fetches():
    handles = [f"p{i}" for i in range(50)]
    calls = {"n": 0}

    class Counting(FakeH1):
        def get_structured_scopes(self, handle):
            calls["n"] += 1
            return super().get_structured_scopes(handle)

    h1 = Counting(_progs(*handles), {h: [repo(h)] for h in handles})
    select_programs(h1, want=3, inspect_limit=10)
    assert calls["n"] <= 10
