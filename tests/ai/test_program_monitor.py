"""Program monitor — new/scope/reward/pause/resume detection and pause->inactive."""

from __future__ import annotations

from pathlib import Path

from aegis.ai import program_monitor as pm
from aegis.ai.registry import Program, load_registry, save_registry


def _p(handle, platform="hackerone", targets=None, reward=0, active=True, oos=None):
    return Program(handle=handle, platform=platform, targets=targets or [],
                   reward_ceiling=reward, active=active, out_of_scope=oos or [])


def test_diff_detects_new_program():
    old = {}
    fresh = {"acme": _p("acme", targets=["a/b"], reward=1000)}
    evs = pm.diff(old, fresh, {"hackerone"})
    assert [e.type for e in evs] == ["new_program"] and evs[0].handle == "acme"


def test_diff_detects_scope_change():
    old = {"acme": _p("acme", targets=["a/b"])}
    fresh = {"acme": _p("acme", targets=["a/b", "a/c"], oos=["deps"])}
    evs = [e for e in pm.diff(old, fresh, {"hackerone"}) if e.type == "scope_changed"]
    assert evs and "a/c" in evs[0].added


def test_diff_detects_reward_change():
    old = {"acme": _p("acme", reward=1000)}
    fresh = {"acme": _p("acme", reward=5000)}
    evs = [e for e in pm.diff(old, fresh, {"hackerone"}) if e.type == "reward_changed"]
    assert evs and "5000" in evs[0].detail


def test_diff_detects_pause_only_for_fetched_platform():
    old = {"gone": _p("gone", platform="hackerone"), "other": _p("other", platform="bugcrowd")}
    fresh = {}
    # only hackerone answered -> only 'gone' is paused; 'other' (bugcrowd down) is NOT
    evs = [e for e in pm.diff(old, fresh, {"hackerone"}) if e.type == "paused"]
    assert [e.handle for e in evs] == ["gone"]


def test_diff_detects_resume():
    old = {"acme": _p("acme", active=False)}
    fresh = {"acme": _p("acme", active=True)}
    evs = [e for e in pm.diff(old, fresh, {"hackerone"}) if e.type == "resumed"]
    assert evs and evs[0].handle == "acme"


def test_apply_marks_paused_inactive_and_preserves_annotations():
    old = {"gone": _p("gone", platform="hackerone"),
           "acme": Program(handle="acme", platform="hackerone", targets=["a/b"],
                           audits=3, notes="hand")}
    fresh = {"acme": _p("acme", platform="hackerone", targets=["a/b", "a/c"])}
    merged = pm._apply(old, fresh, {"hackerone"})
    assert merged["gone"].active is False                     # paused
    assert merged["acme"].targets == ["a/b", "a/c"]           # scope refreshed
    assert merged["acme"].audits == 3 and merged["acme"].notes == "hand"  # annotations kept


def test_monitor_end_to_end_writes_alerts(tmp_path: Path):
    store = tmp_path / "programs.json"
    save_registry([_p("stale", platform="bugcrowd", targets=["x/y"], reward=100)], store)

    _BUG = [{"name": "New Co", "url": "https://bugcrowd.com/newco", "max_payout": 9000,
             "targets": {"in_scope": [{"target": "https://github.com/newco/api"}],
                         "out_of_scope": []}}]

    def fake(url):
        return _BUG if "bugcrowd_data" in url else []

    summary = pm.monitor(store, fetch_json=fake)
    assert summary["counts"].get("new_program") == 1        # newco appeared
    assert summary["counts"].get("paused") == 1             # stale gone from bugcrowd feed
    progs = {p.handle: p for p in load_registry(store)}
    assert progs["bugcrowd-newco"].reward_ceiling == 9000
    assert progs["stale"].active is False                   # paused -> inactive
    alerts = pm.load_alerts(tmp_path)
    assert any(a["type"] == "new_program" for a in alerts)


def test_monitor_no_feed_skips(tmp_path: Path):
    store = tmp_path / "programs.json"
    save_registry([_p("keep", targets=["a/b"])], store)
    summary = pm.monitor(store, fetch_json=lambda url: [])   # nothing answers
    assert summary.get("error") and summary["events"] == []
    # registry untouched -> 'keep' still active (no false pause)
    assert load_registry(store)[0].active is True
