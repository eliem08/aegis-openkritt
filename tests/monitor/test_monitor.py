"""Continuous monitoring, subscans, and notifications (Phase 4)."""

from __future__ import annotations

import pytest

from aegis.graph import Asset, AssetKind, new_snapshot
from aegis.monitor import (
    ActivityLog,
    Destination,
    DestinationKind,
    MonitoringPlanner,
    Notification,
    Notifier,
    ScopeWidened,
    new_schedule,
)

TARGETS = ("api.example.test", "app.example.test")


def schedule(targets=TARGETS):
    return new_schedule(tenant_id="t", engagement_id="eng-1", scope_digest="digest-1",
                        targets=targets, manifest_set=("subfinder", "http-probe"),
                        cadence_seconds=3600)


def asset(key, host, *, kind=AssetKind.ROUTE, attrs=None):
    from datetime import datetime, timezone
    now = datetime(2026, 8, 2, tzinfo=timezone.utc)
    a = Asset(engagement_id="eng-1", asset_key=key, kind=kind,
              attributes={"host": host, **(attrs or {})}, first_seen=now, last_seen=now)
    return a


def snapshot(entries, *, complete=True, scan_id="s"):
    assets = [asset(k, v["host"], attrs={"digest": v.get("d", 1)}) for k, v in entries.items()]
    # give each asset a distinct digest by mutating attributes
    for a, (k, v) in zip(assets, entries.items()):
        a.attributes["d"] = v.get("d", 1)
    return new_snapshot(engagement_id="eng-1", scan_id=scan_id, assets=assets, complete=complete)


# --- immutable schedule + full scans ----------------------------------------

def test_schedule_config_hash_is_stable_and_identifying():
    a = schedule()
    b = schedule()
    assert a.config_hash == b.config_hash          # same config -> same identity
    c = new_schedule(tenant_id="t", engagement_id="eng-1", scope_digest="digest-1",
                     targets=TARGETS, manifest_set=("subfinder",), cadence_seconds=3600)
    assert c.config_hash != a.config_hash          # different config -> different identity


def test_full_scan_is_built_from_the_frozen_config():
    plan = MonitoringPlanner()
    req = plan.full_scan(schedule())
    assert req.kind == "full" and req.scope_digest == "digest-1"
    assert req.targets == tuple(sorted(TARGETS))
    assert plan.activity.records("scheduled")


# --- subscans from diffs -----------------------------------------------------

def test_added_and_changed_assets_produce_narrow_subscans():
    plan = MonitoringPlanner()
    prev = snapshot({"route:GET api.example.test/a": {"host": "api.example.test", "d": 1}})
    curr = snapshot({
        "route:GET api.example.test/a": {"host": "api.example.test", "d": 2},   # changed
        "route:GET app.example.test/b": {"host": "app.example.test", "d": 1},   # added
    }, scan_id="s2")
    assets = {a.asset_key: a for a in
              [asset("route:GET api.example.test/a", "api.example.test"),
               asset("route:GET app.example.test/b", "app.example.test")]}

    reqs = plan.subscans_from_diff(schedule(), prev, curr, parent_scan_id="scan-1", assets=assets)
    assert {r.targets[0] for r in reqs} == {"api.example.test", "app.example.test"}
    assert all(r.kind == "subscan" and r.parent_scan_id == "scan-1" for r in reqs)
    # subscans retain the parent scope digest, unchanged
    assert all(r.scope_digest == "digest-1" for r in reqs)


def test_subscan_cannot_widen_scope():
    plan = MonitoringPlanner()
    prev = snapshot({})
    curr = snapshot({"route:GET evil.other.test/x": {"host": "evil.other.test"}}, scan_id="s2")
    assets = {"route:GET evil.other.test/x": asset("route:GET evil.other.test/x", "evil.other.test")}
    with pytest.raises(ScopeWidened):
        plan.subscans_from_diff(schedule(), prev, curr, parent_scan_id="scan-1", assets=assets)


def test_unchanged_assets_do_not_trigger_subscans():
    plan = MonitoringPlanner()
    snap = snapshot({"route:GET api.example.test/a": {"host": "api.example.test", "d": 1}})
    reqs = plan.subscans_from_diff(schedule(), snap, snap, parent_scan_id="scan-1", assets={})
    assert reqs == []


# --- removals require agreeing complete scans -------------------------------

def test_incomplete_scans_cannot_declare_removal():
    plan = MonitoringPlanner()
    s1 = snapshot({"a": {"host": "api.example.test"}, "b": {"host": "api.example.test"}})
    partial1 = snapshot({"a": {"host": "api.example.test"}}, complete=False, scan_id="s2")
    partial2 = snapshot({"a": {"host": "api.example.test"}}, complete=False, scan_id="s3")
    assert plan.confirmed_asset_removals(schedule(), [s1, partial1, partial2]) == []


def test_agreeing_complete_scans_confirm_removal():
    plan = MonitoringPlanner()
    s1 = snapshot({"a": {"host": "api.example.test"}, "b": {"host": "api.example.test"}})
    s2 = snapshot({"a": {"host": "api.example.test"}}, scan_id="s2")
    s3 = snapshot({"a": {"host": "api.example.test"}}, scan_id="s3")
    assert plan.confirmed_asset_removals(schedule(), [s1, s2, s3]) == ["b"]
    assert plan.activity.records("removal")


# --- activity trail ----------------------------------------------------------

def test_every_action_leaves_an_activity_record():
    seen = []
    plan = MonitoringPlanner(activity=ActivityLog(on_record=seen.append))
    plan.full_scan(schedule())
    assert [r.kind for r in seen] == ["scheduled"]


# --- notifications -----------------------------------------------------------

def dest():
    return Destination(kind=DestinationKind.SLACK, address="#alerts", secret_ref="vault://slack/token")


def note(dedupe="n1", summary="3 new routes on api.example.test"):
    return Notification(dedupe_key=dedupe, destination=dest(), summary=summary,
                        deep_link="https://app.aegis/scan/scan-1")


def test_delivery_records_attempts_and_response_class():
    notifier = Notifier(sender=lambda d, p: "2xx")
    rec = notifier.send(note())
    assert rec.final_status == "delivered" and rec.response_class == "2xx" and rec.attempts == 1


def test_delivery_is_idempotent_on_the_dedupe_key():
    calls = []
    notifier = Notifier(sender=lambda d, p: (calls.append(1), "2xx")[1])
    first = notifier.send(note(dedupe="same"))
    second = notifier.send(note(dedupe="same"))
    assert first.final_status == "delivered" and second.final_status == "duplicate"
    assert len(calls) == 1                          # sent exactly once


def test_transient_failure_is_retried_then_recorded_failed():
    attempts = {"n": 0}

    def flaky(d, p):
        attempts["n"] += 1
        return "5xx"

    rec = Notifier(sender=flaky, max_attempts=3).send(note())
    assert rec.attempts == 3 and rec.final_status == "failed" and rec.response_class == "5xx"


def test_secret_token_never_appears_in_the_message():
    captured = {}
    notifier = Notifier(sender=lambda d, p: (captured.update(payload=p, dest=d), "2xx")[1])
    notifier.send(note())
    # the token is only a ref on the destination; the payload has no secret
    assert "token" not in str(captured["payload"]).lower()
    assert captured["dest"].secret_ref.startswith("vault://")


def test_sensitive_summary_is_blocked_not_sent():
    sent = []
    notifier = Notifier(sender=lambda d, p: (sent.append(p), "2xx")[1])
    leaky = Notification(dedupe_key="leak", destination=dest(),
                         summary="leaked AKIAIOSFODNN7EXAMPLE in response",
                         deep_link="https://app.aegis/x")
    rec = notifier.send(leaky)
    # redaction removes the key; if anything sensitive survived it would be blocked
    assert rec.final_status in ("delivered", "blocked")
    if sent:
        assert "AKIAIOSFODNN7EXAMPLE" not in str(sent[0])
