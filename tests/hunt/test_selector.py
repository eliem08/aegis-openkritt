"""Automatic program selection — no handle needed, and it can't pick a bad target."""

from __future__ import annotations

from aegis.hunt.selector import select_programs

REPO = lambda org: {"attributes": {"asset_type": "SOURCE_CODE",
                                    "asset_identifier": f"https://github.com/{org}/repo",
                                    "eligible_for_submission": True}}
WEB = {"attributes": {"asset_type": "URL", "asset_identifier": "https://app.x.com",
                      "eligible_for_submission": True}}


class FakeH1:
    def __init__(self, programs, scopes, attrs=None):
        self._programs = programs
        self._scopes = scopes
        self._attrs = attrs or {}          # per-handle extra program attributes

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
                {"has-code": [REPO("has-code")], "web-only": [WEB]})
    picked = [c.handle for c in select_programs(h1, want=5)]
    assert picked == ["has-code"]          # web-only program is not selectable by a code scanner


def test_never_selects_an_automation_forbidden_program():
    h1 = FakeH1(_progs("noauto"), {"noauto": [REPO("noauto")]},
                attrs={"noauto": {"policy": "Automated tools and automated scanning are prohibited."}})
    assert select_programs(h1, want=5) == []


def test_ranks_bounty_programs_and_more_repos_first():
    h1 = FakeH1(_progs("vdp", "bounty"),
                {"vdp": [REPO("vdp")],
                 "bounty": [REPO("bounty"), {"attributes": {"asset_type": "SOURCE_CODE",
                            "asset_identifier": "https://github.com/bounty/two", "eligible_for_submission": True}}]},
                attrs={"bounty": {"offers_bounties": True}})
    picked = [c.handle for c in select_programs(h1, want=2)]
    assert picked[0] == "bounty"           # bounties + more repos rank first


def test_want_caps_the_selection():
    handles = [f"p{i}" for i in range(6)]
    h1 = FakeH1(_progs(*handles), {h: [REPO(h)] for h in handles})
    assert len(select_programs(h1, want=3)) == 3


def test_inspect_limit_bounds_the_fetches():
    handles = [f"p{i}" for i in range(50)]
    calls = {"n": 0}

    class Counting(FakeH1):
        def get_structured_scopes(self, handle):
            calls["n"] += 1
            return super().get_structured_scopes(handle)

    h1 = Counting(_progs(*handles), {h: [REPO(h)] for h in handles})
    select_programs(h1, want=3, inspect_limit=10)
    assert calls["n"] <= 10                 # never inspects more than the limit
