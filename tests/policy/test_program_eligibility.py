"""Regression tests for the program-eligibility gate.

Each of the three costly scope misses this session is pinned as a test so we can
never silently repeat it: pipelinewise (de-scoped), Nextcloud (suspended),
Netflix/dispatch (in the exclusion section of the page).
"""

from __future__ import annotations

from aegis.policy.program_eligibility import (
    Eligibility,
    canonical_repo,
    verify_target,
)


def test_canonical_repo_variants():
    assert canonical_repo("https://github.com/Netflix/dispatch") == "netflix/dispatch"
    assert canonical_repo("github.com/cashapp/hermit") == "cashapp/hermit"
    assert canonical_repo("git@github.com:matomo-org/tag-manager.git") == "matomo-org/tag-manager"
    assert canonical_repo("cashapp/hermit") == "cashapp/hermit"
    assert canonical_repo("https://wise.com") is None          # host, not a repo
    assert canonical_repo("") is None


def test_pipelinewise_moved_out_of_scope():
    """A repo present in out_of_scope is NOT eligible even if a stale target list lists it."""
    wise = {
        "handle": "bugcrowd-wise",
        "active": True,
        "reward_ceiling": 4000.0,
        "targets": ["transferwise/pipelinewise", "github.com/transferwise/*"],
        "bounty_eligible_targets": [],
        "out_of_scope": ["docs.wise.com", "github.com/transferwise/pipelinewise"],
        "scope_text": "In scope: wise.com. github.com/transferwise/* (Recon).",
    }
    r = verify_target(wise, "github.com/transferwise/pipelinewise")
    assert r.verdict is Eligibility.NOT_ELIGIBLE
    assert not r.submittable_for_cash
    assert "out-of-scope" in " ".join(r.reasons).lower()


def test_nextcloud_suspended_is_credit_only():
    """A suspended/recognition-only program pays no cash even with historical ceilings."""
    nc = {
        "handle": "nextcloud",
        "active": True,
        "reward_ceiling": 5000.0,  # historical, still shown on the page
        "bounty_eligible_targets": ["nextcloud/server", "nextcloud/deck"],
        "targets": ["nextcloud/server", "nextcloud/deck"],
        "out_of_scope": [],
        "scope_text": (
            "No monetary bounties. Due to AI-generated reports we have temporarily "
            "suspended our paid bounty program and no financial rewards will be "
            "awarded for any submissions, regardless of severity."
        ),
    }
    r = verify_target(nc, "nextcloud/deck")
    assert r.verdict is Eligibility.CREDIT_ONLY
    assert r.pays_cash is False
    assert "suspend" in " ".join(r.reasons).lower()


def _netflix_program():
    return {
        "handle": "netflix",
        "active": True,
        "reward_ceiling": 25000.0,
        "bounty_eligible_targets": ["Netflix/zuul", "Netflix/atlas", "Netflix/spectator"],
        "targets": ["Netflix/zuul", "Netflix/atlas", "Netflix/spectator"],
        "out_of_scope": [],  # dispatch/consoleme live in the policy TEXT's exclusion section
        "scope_text": (
            "Open Source Targets: Primary: Zuul https://github.com/Netflix/zuul. "
            "Secondary: Atlas, Spectator.\n"
            "Out-of-Scope (Please Read):\n"
            "Dispatch OSS (https://github.com/Netflix/dispatch)\n"
            "ConsoleMe OSS (https://github.com/Netflix/consoleme)\n"
            "Weep OSS (https://github.com/Netflix/weep)\n"
        ),
    }


def test_netflix_dispatch_excluded_in_policy_text():
    r = verify_target(_netflix_program(), "https://github.com/Netflix/dispatch")
    assert r.verdict is Eligibility.NOT_ELIGIBLE
    assert not r.submittable_for_cash
    assert "exclusion" in " ".join(r.reasons).lower() or "out-of-scope" in " ".join(r.reasons).lower()


def test_netflix_consoleme_excluded_in_policy_text():
    r = verify_target(_netflix_program(), "github.com/Netflix/consoleme")
    assert r.verdict is Eligibility.NOT_ELIGIBLE


def test_netflix_zuul_is_submittable():
    """The structured eligible list must win over free-text noise near exclusions."""
    r = verify_target(_netflix_program(), "https://github.com/Netflix/zuul")
    assert r.verdict is Eligibility.SUBMITTABLE
    assert r.submittable_for_cash


def test_hermit_submittable():
    bos = {
        "handle": "bugcrowd-blockopensource",
        "active": True,
        "reward_ceiling": 5000.0,
        "bounty_eligible_targets": [
            "cashapp/misk", "cashapp/hermit", "square/okhttp", "square/okio", "square/wire",
        ],
        "targets": ["cashapp/misk", "cashapp/hermit", "square/okhttp"],
        "out_of_scope": [],
        "scope_text": "Block OSS projects from Square, Cash App, and Afterpay Github organizations.",
    }
    r = verify_target(bos, "cashapp/hermit")
    assert r.verdict is Eligibility.SUBMITTABLE
    assert r.submittable_for_cash


def test_recon_only_github_wildcard():
    wise = {
        "handle": "bugcrowd-wise",
        "active": True,
        "reward_ceiling": 4000.0,
        "targets": ["github.com/transferwise/*"],
        "bounty_eligible_targets": [],
        "out_of_scope": ["github.com/transferwise/pipelinewise"],
        "scope_text": (
            "github.com/transferwise/* is tagged Recon. Third-party library bugs "
            "will not be rewarded."
        ),
    }
    r = verify_target(wise, "github.com/transferwise/tw-tasks-executor")
    assert r.verdict is Eligibility.RECON_ONLY


def test_unknown_fails_closed():
    prog = {
        "handle": "some-program",
        "active": True,
        "reward_ceiling": 10000.0,
        "targets": ["someorg/coolrepo"],
        "bounty_eligible_targets": ["someorg/coolrepo"],
        "out_of_scope": [],
        "scope_text": "In scope: someorg/coolrepo",
    }
    r = verify_target(prog, "someorg/totally-different-repo")
    assert r.verdict is Eligibility.UNKNOWN
    assert not r.submittable_for_cash


def test_inactive_program_not_eligible():
    prog = {
        "handle": "dead-program",
        "active": False,
        "reward_ceiling": 10000.0,
        "bounty_eligible_targets": ["someorg/repo"],
        "targets": ["someorg/repo"],
        "out_of_scope": [],
        "scope_text": "",
    }
    r = verify_target(prog, "someorg/repo")
    assert r.verdict is Eligibility.NOT_ELIGIBLE
