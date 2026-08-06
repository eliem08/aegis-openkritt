"""Program importers: bounty-targets-data + Code4rena mapping, and registry merge."""

from __future__ import annotations

from pathlib import Path

from aegis.ai.program_sources import (
    BountyTargetsSource,
    Code4renaSource,
    _map_generic,
    import_programs,
    repo_from_asset,
)
from aegis.ai.registry import Program, load_registry, save_registry

# --- representative (trimmed) payloads mirroring the real feed shapes ---
_HACKERONE = [{
    "name": "Acme", "url": "https://hackerone.com/acme", "handle": "acme",
    "offers_bounties": True,
    "targets": {"in_scope": [
        {"asset_identifier": "https://github.com/acme/api", "asset_type": "SOURCE_CODE"},
        {"asset_identifier": "*.acme.com", "asset_type": "WILDCARD"}],
        "out_of_scope": [{"asset_identifier": "blog.acme.com"}]},
}]
_IMMUNEFI = [{
    "name": "VaultFi", "url": "https://immunefi.com/bounty/vaultfi", "maxBounty": 250000,
    "assets": [{"url": "https://github.com/vaultfi/contracts", "type": "smart_contract"}],
}]
_BUGCROWD = [{
    "name": "Globex", "url": "https://bugcrowd.com/globex", "max_payout": 5000,
    "targets": {"in_scope": [{"target": "https://github.com/globex/web", "type": "source"}],
                "out_of_scope": []},
}]
_C4 = [
    {"full_name": "code-423n4/2026-01-freshdefi", "name": "2026-01-freshdefi",
     "html_url": "https://github.com/code-423n4/2026-01-freshdefi",
     "description": "Fresh DeFi audit", "archived": False, "fork": False},
    {"full_name": "code-423n4/old", "name": "old", "archived": True, "fork": False},
]


def _fake_fetch(url: str):
    if "hackerone_data" in url:
        return _HACKERONE
    if "bugcrowd_data" in url:
        return _BUGCROWD
    if "code-423n4" in url:
        return _C4
    return []


def test_repo_from_asset():
    assert repo_from_asset("https://github.com/acme/api") == "acme/api"
    assert repo_from_asset("git@github.com:acme/api.git") == "acme/api"
    assert repo_from_asset("*.acme.com") == ""


def test_bountytargets_maps_source_repos_and_rewards():
    src = BountyTargetsSource(platforms=("hackerone", "bugcrowd"))
    src.fetch_json = _fake_fetch
    progs = {p.handle: p for p in src.fetch()}
    assert progs["acme"].targets == ["acme/api"]                 # github asset -> repo
    assert "In scope" in progs["acme"].scope_text
    assert progs["bugcrowd-globex"].reward_ceiling == 5000


def test_map_generic_handles_immunefi_style_contract_entry():
    # Immunefi isn't in the feed, but the mapper still handles an assets+maxBounty shape
    # if such a record is added manually — kind=contract, repo + reward extracted.
    prog = _map_generic("immunefi", _IMMUNEFI[0])
    assert prog.kind == "contract" and prog.reward_ceiling == 250000
    assert prog.targets == ["vaultfi/contracts"]


def test_bountytargets_source_code_only_filters():
    src = BountyTargetsSource(platforms=("hackerone",), source_code_only=True)
    src.fetch_json = _fake_fetch
    # acme has a source repo -> kept
    assert [p.handle for p in src.fetch()] == ["acme"]


def test_code4rena_skips_archived():
    src = Code4renaSource()
    src.fetch_json = _fake_fetch
    progs = src.fetch()
    assert [p.handle for p in progs] == ["code4rena-2026-01-freshdefi"]
    assert progs[0].kind == "contract" and progs[0].targets == ["code-423n4/2026-01-freshdefi"]


def test_import_merges_without_clobbering_annotations(tmp_path: Path):
    store = tmp_path / "programs.json"
    # operator has already annotated acme with audit history + a reward
    save_registry([Program(handle="acme", audits=3, age_months=20, paid_reports=40,
                           reward_ceiling=9999, notes="hand-checked")], store)
    summary = import_programs(["bountytargets"], store=store, fetch_json=_fake_fetch)
    progs = {p.handle: p for p in load_registry(store)}
    acme = progs["acme"]
    assert acme.audits == 3 and acme.age_months == 20 and acme.paid_reports == 40  # preserved
    assert acme.reward_ceiling == 9999 and acme.notes == "hand-checked"            # preserved
    assert acme.targets == ["acme/api"]                                           # refreshed from feed
    assert summary["updated"] == 1 and summary["added"] >= 1                       # immunefi/bugcrowd new


def test_import_summary_counts(tmp_path: Path):
    store = tmp_path / "programs.json"
    summary = import_programs(["bountytargets", "code4rena"], store=store, fetch_json=_fake_fetch)
    assert summary["total_in_registry"] >= 3
    assert summary["with_source_repo"] >= 3
