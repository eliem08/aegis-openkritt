"""Authenticated platform connectors: blocked-without-creds (never invent creds), and
response->Program mappers validated against representative fixtures. No network."""

from __future__ import annotations

import pytest

from aegis.ai import program_connectors as pc


# ------- blocked by default (no credentials) -------------------------------------------------
@pytest.mark.parametrize("cls,envs", [
    (pc.HackerOneConnector, ("HACKERONE_API_USERNAME", "HACKERONE_API_TOKEN", "H1_API_USERNAME",
                             "H1_API_TOKEN")),
    (pc.BugcrowdConnector, ("BUGCROWD_API_TOKEN", "BUGCROWD_TOKEN")),
    (pc.IntigritiConnector, ("INTIGRITI_API_TOKEN", "INTIGRITI_TOKEN")),
    (pc.YesWeHackConnector, ("YESWEHACK_API_TOKEN", "YWH_API_TOKEN")),
])
def test_connector_blocked_without_creds(cls, envs, monkeypatch):
    for e in envs:
        monkeypatch.delenv(e, raising=False)
    src = cls()
    assert src.available() is False
    assert src.blocked_reason()                 # explains what to set
    assert src.fetch() == []                    # never invents creds / scrapes around auth


def test_immunefi_always_blocked():
    src = pc.ImmunefiConnector()
    assert src.available() is False
    assert "no official" in src.blocked_reason().lower()
    assert src.fetch() == []


def test_connector_status_is_offline_and_reports_reasons(monkeypatch):
    for e in ("HACKERONE_API_USERNAME", "HACKERONE_API_TOKEN", "BUGCROWD_API_TOKEN",
              "INTIGRITI_API_TOKEN", "YESWEHACK_API_TOKEN"):
        monkeypatch.delenv(e, raising=False)
    statuses = pc.connector_status()
    by = {s.name: s for s in statuses}
    assert set(by) == set(pc.CONNECTORS)
    assert all(s.available is False for s in statuses)          # nothing available in test env
    assert all(s.blocked_reason for s in statuses)


# ------- mappers: documented response shapes -> canonical Program ----------------------------
def test_hackerone_map_program_and_scopes():
    prog = pc.HackerOneConnector.map_program({
        "type": "program", "attributes": {"handle": "acme", "submission_state": "open",
                                           "offers_bounties": True, "max_bounty": 10000,
                                           "policy": "test only in scope assets"}})
    assert prog.platform == "hackerone" and prog.handle == "acme"
    assert prog.reward_ceiling == 10000 and prog.active is True
    # structured scopes fold in repos + out-of-scope
    pc.HackerOneConnector.apply_scopes(prog, {"data": [
        {"attributes": {"asset_identifier": "https://github.com/acme/backend",
                        "eligible_for_submission": True}},
        {"attributes": {"asset_identifier": "https://github.com/acme/legacy",
                        "eligible_for_submission": False}}]})
    assert "acme/backend" in prog.targets
    assert any("acme/legacy" in s for s in prog.out_of_scope)


def test_hackerone_paused_program_inactive():
    prog = pc.HackerOneConnector.map_program(
        {"attributes": {"handle": "paused", "submission_state": "paused"}})
    assert prog.active is False


def test_bugcrowd_map_program():
    prog = pc.BugcrowdConnector.map_program({
        "attributes": {"code": "acme", "name": "Acme", "max_reward": 5000,
                       "in_scope": ["https://github.com/acme/api"]},
        "links": {"self": "https://bugcrowd.com/acme"}})
    assert prog.handle == "bugcrowd-acme" and prog.platform == "bugcrowd"
    assert prog.reward_ceiling == 5000 and "acme/api" in prog.targets


def test_intigriti_map_program():
    prog = pc.IntigritiConnector.map_program({
        "handle": "acme", "name": "Acme", "status": "open", "maxBounty": 7500,
        "confidentialityLevel": "public",
        "domains": ["https://github.com/acme/web"]})
    assert prog.handle == "intigriti-acme" and prog.reward_ceiling == 7500
    assert "acme/web" in prog.targets and prog.active is True


def test_yeswehack_map_program():
    prog = pc.YesWeHackConnector.map_program({
        "slug": "acme", "title": "Acme", "public_status": "open", "max_bounty": 3000,
        "scopes": ["https://github.com/acme/mobile"]})
    assert prog.handle == "yeswehack-acme" and prog.reward_ceiling == 3000
    assert "acme/mobile" in prog.targets


def test_hackerone_fetch_with_injected_transport(monkeypatch):
    monkeypatch.setenv("HACKERONE_API_USERNAME", "u")
    monkeypatch.setenv("HACKERONE_API_TOKEN", "t")
    pages = {
        "https://api.hackerone.com/v1/hackers/programs?page[size]=100": {
            "data": [{"attributes": {"handle": "acme", "submission_state": "open",
                                     "max_bounty": 1000}}],
            "links": {"next": "https://api.hackerone.com/v1/hackers/programs?page=2"}},
        "https://api.hackerone.com/v1/hackers/programs?page=2": {
            "data": [{"attributes": {"handle": "beta", "submission_state": "open"}}],
            "links": {}},
    }
    src = pc.HackerOneConnector()
    src.fetch_json = lambda url, headers=None: pages[url]     # inject transport
    progs = src.fetch()
    assert {p.handle for p in progs} == {"acme", "beta"}
    assert all(p.platform == "hackerone" for p in progs)


def test_fetch_connectors_reports_blocked_and_survives(monkeypatch):
    for e in ("HACKERONE_API_USERNAME", "HACKERONE_API_TOKEN", "BUGCROWD_API_TOKEN",
              "INTIGRITI_API_TOKEN", "YESWEHACK_API_TOKEN"):
        monkeypatch.delenv(e, raising=False)
    res = pc.fetch_connectors()
    assert res.programs == []                                  # nothing available -> no programs
    assert len(res.statuses) == len(pc.CONNECTORS)
    assert all(not s.available for s in res.statuses)
