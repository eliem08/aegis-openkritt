"""Asset/observation graph: natural keys, provenance-preserving dedup, and
snapshot diffs that never turn a partial scan into a removal (Phase 2)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aegis.adapters import AdapterEvent, EventKind
from aegis.graph import (
    OUT_OF_SCOPE,
    UNPARSEABLE,
    WILDCARD,
    Asset,
    AssetKind,
    DiffStatus,
    Normalizer,
    canonical_url,
    confirmed_removals,
    diff_snapshots,
    domain_key,
    merge_into,
    new_snapshot,
    parameter_key,
    route_key,
    service_key,
    technology_key,
    url_key,
)
from aegis.policy.scope import ScopeGuard

NOW = datetime(2026, 8, 2, 12, 0, tzinfo=timezone.utc)
SCOPE = ScopeGuard(["api.example.test", "*.example.test"])


def event(kind, data, *, source="fake", target="api.example.test", observed_at=None, confidence=1.0):
    return AdapterEvent(
        kind=kind, source=source, observed_at=observed_at or NOW, target=target,
        task_id="tk", adapter_version="1.0.0", data=data, confidence=confidence,
    )


def normalizer(scope=SCOPE):
    return Normalizer(scope=scope, engagement_id="eng-1", scan_id="scan-1")


# --- natural keys ------------------------------------------------------------

def test_natural_keys_distinguish_kinds():
    keys = {
        domain_key("API.Example.Test."),
        service_key("api.example.test", 443, "https"),
        url_key("https://api.example.test/health"),
        route_key("api.example.test", "get", "/users/{id}"),
        technology_key("api.example.test", "nginx"),
    }
    assert len(keys) == 5  # every kind gets its own identity
    assert domain_key("API.Example.Test.") == "domain:api.example.test"


@pytest.mark.parametrize("a,b", [
    ("https://api.example.test/health", "HTTPS://API.example.test:443/health/"),
    ("https://api.example.test/search?q=1&page=2", "https://api.example.test/search?page=9&q=zzz"),
])
def test_urls_canonicalize_to_one_key(a, b):
    assert url_key(a) == url_key(b)


def test_canonical_url_keeps_parameter_names_but_not_values():
    assert canonical_url("https://api.example.test/s?q=secret&page=2") == \
        "https://api.example.test/s?page&q"


def test_parameters_are_scoped_to_their_route():
    r1 = route_key("api.example.test", "GET", "/a")
    r2 = route_key("api.example.test", "GET", "/b")
    assert parameter_key(r1, "id") != parameter_key(r2, "id")


# --- normalization -----------------------------------------------------------

def test_asset_and_route_events_become_typed_assets():
    result = normalizer().normalize([
        event(EventKind.ASSET, {"identifier": "api.example.test", "asset_type": "domain"}),
        event(EventKind.ROUTE, {"method": "GET", "path": "/users/{id}",
                                "parameters": [{"name": "id", "location": "path"}]}),
        event(EventKind.TECHNOLOGY, {"name": "nginx", "version": "1.25"}),
    ])
    kinds = sorted(a.kind.value for a in result.assets.values())
    assert kinds == ["domain", "parameter", "route", "technology"]
    assert not result.rejections


def test_control_events_are_not_assets():
    result = normalizer().normalize([
        event(EventKind.PROGRESS, {"message": "starting"}),
        event(EventKind.TERMINAL, {"status": "succeeded"}),
        event(EventKind.DIAGNOSTIC, {"message": "provider timeout"}),
        event(EventKind.SECRET_CANDIDATE, {"kind_hint": "aws_key"}),
    ])
    assert result.assets == {} and result.observations == [] and result.rejections == []


def test_out_of_scope_asset_is_rejected():
    result = normalizer().normalize([
        event(EventKind.ASSET, {"identifier": "evil.other.test", "asset_type": "domain"}),
    ])
    assert result.assets == {}
    assert [r.reason for r in result.rejections] == [OUT_OF_SCOPE]


@pytest.mark.parametrize("data", [
    {"identifier": "*.example.test", "asset_type": "domain"},
    {"identifier": "anything.example.test", "asset_type": "domain", "wildcard": True},
])
def test_wildcard_results_are_suppressed(data):
    result = normalizer().normalize([event(EventKind.ASSET, data)])
    assert result.assets == {}
    assert [r.reason for r in result.rejections] == [WILDCARD]


def test_malformed_event_is_rejected_not_raised():
    result = normalizer().normalize([
        event(EventKind.ASSET, {"asset_type": "domain"}),           # no identifier
        event(EventKind.ROUTE, {"method": "GET"}),                   # no path
        event(EventKind.ASSET, {"identifier": "api.example.test"}),  # still works
    ])
    assert [r.reason for r in result.rejections] == [UNPARSEABLE, UNPARSEABLE]
    assert len(result.assets) == 1  # the good one still landed


# --- provenance --------------------------------------------------------------

def test_provenance_survives_multi_source_deduplication():
    subfinder = normalizer().normalize([
        event(EventKind.ASSET, {"identifier": "api.example.test", "asset_type": "domain",
                                "provider": "crtsh"}, source="subfinder"),
    ])
    gau = normalizer().normalize([
        event(EventKind.ASSET, {"identifier": "API.example.test.", "asset_type": "domain",
                                "provider": "wayback"}, source="gau"),
    ])
    merged = merge_into(dict(subfinder.assets), gau.assets)

    assert len(merged) == 1  # deduplicated to one asset
    asset = merged[domain_key("api.example.test")]
    assert asset.sources == ["gau/wayback", "subfinder/crtsh"]  # every source retained
    assert asset.observation_count == 2
    # ...and the underlying observations are untouched, one per sighting
    assert len(subfinder.observations) == 1 and len(gau.observations) == 1


def test_observations_are_immutable():
    result = normalizer().normalize([
        event(EventKind.ASSET, {"identifier": "api.example.test", "asset_type": "domain"})])
    with pytest.raises(Exception):
        result.observations[0].asset_key = "tampered"


def test_first_and_last_seen_track_the_observation_window():
    later = NOW + timedelta(hours=3)
    result = normalizer().normalize([
        event(EventKind.ASSET, {"identifier": "api.example.test", "asset_type": "domain"}),
        event(EventKind.ASSET, {"identifier": "api.example.test", "asset_type": "domain"},
              observed_at=later),
    ])
    asset = next(iter(result.assets.values()))
    assert asset.first_seen == NOW and asset.last_seen == later


# --- snapshots + diffs -------------------------------------------------------

def asset(key, *, attributes=None, sources=("fake",)):
    a = Asset(engagement_id="eng-1", asset_key=key, kind=AssetKind.DOMAIN,
              attributes=dict(attributes or {}), sources=list(sources),
              first_seen=NOW, last_seen=NOW)
    return a


def snapshot(keys_with_attrs, *, complete=True, scan_id="s1"):
    assets = [asset(k, attributes=v) for k, v in keys_with_attrs.items()]
    return new_snapshot(engagement_id="eng-1", scan_id=scan_id, assets=assets, complete=complete)


def test_diff_labels_added_changed_unchanged_missing():
    prev = snapshot({"a": {"v": 1}, "b": {"v": 1}, "c": {"v": 1}})
    curr = snapshot({"a": {"v": 1}, "b": {"v": 2}, "d": {"v": 1}}, scan_id="s2")

    d = diff_snapshots(prev, curr)
    assert d.added == ["d"] and d.changed == ["b"]
    assert d.unchanged == ["a"] and d.missing == ["c"]
    assert d.status("d") is DiffStatus.ADDED and d.status("c") is DiffStatus.MISSING


def test_first_scan_is_all_added_and_not_removal_safe():
    d = diff_snapshots(None, snapshot({"a": {}}))
    assert d.added == ["a"] and d.removal_safe is False


def test_incomplete_scan_is_never_removal_safe():
    prev = snapshot({"a": {}})
    partial = snapshot({}, complete=False, scan_id="s2")
    d = diff_snapshots(prev, partial)
    assert d.missing == ["a"]        # visible as missing...
    assert d.removal_safe is False   # ...but not a basis for removal


def test_removal_requires_enough_agreeing_complete_scans():
    s1 = snapshot({"a": {}, "b": {}})
    s2 = snapshot({"a": {}}, scan_id="s2")
    s3 = snapshot({"a": {}}, scan_id="s3")

    assert confirmed_removals([s1, s2], required_agreeing_scans=2) == []   # only one agrees
    assert confirmed_removals([s1, s2, s3], required_agreeing_scans=2) == ["b"]


def test_incomplete_scans_cannot_cause_a_false_removal():
    s1 = snapshot({"a": {}, "b": {}})
    partial1 = snapshot({"a": {}}, complete=False, scan_id="s2")
    partial2 = snapshot({"a": {}}, complete=False, scan_id="s3")
    # Two scans "agree" b is gone, but neither had complete coverage.
    assert confirmed_removals([s1, partial1, partial2], required_agreeing_scans=2) == []


def test_reappearing_asset_is_not_removed():
    s1 = snapshot({"a": {}, "b": {}})
    s2 = snapshot({"a": {}}, scan_id="s2")
    s3 = snapshot({"a": {}, "b": {}}, scan_id="s3")
    assert confirmed_removals([s1, s2, s3], required_agreeing_scans=2) == []
