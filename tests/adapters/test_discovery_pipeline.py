"""Phase 2 pipeline: all five discovery adapters feed one durable, provenance-rich
asset snapshot, with no active payload and no direct network access.

The adapters are driven from their golden fixtures (the pinned binaries are a
deployment/licensing concern), but everything downstream — normalization, scope
and wildcard rejection, deduplication across sources, persistence, and snapshot
completeness — is the real production path.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from aegis.adapters import (
    EventKind,
    ExecutionEnvelope,
    GauAdapter,
    HttpProbeAdapter,
    JsluiceAdapter,
    JsluiceConfig,
    KatanaAdapter,
    SubfinderAdapter,
    discovery_adapters,
)
from aegis.api.persistence import SqliteRepository
from aegis.api.store import EngagementRecord
from aegis.graph import AssetKind, Normalizer, merge_into, new_snapshot
from aegis.policy.scope import ScopeGuard

FIXTURES = Path(__file__).parent / "fixtures"
STUB = "/opt/aegis/tools/stub"
SCOPE = ScopeGuard(["example.test", "*.example.test"])

PIPELINE = [
    (SubfinderAdapter, "subfinder-2.6.6.jsonl", "example.test", {}),
    (GauAdapter, "gau-2.2.4.jsonl", "example.test", {}),
    (HttpProbeAdapter, "http-probe-1.6.9.jsonl", "api.example.test", {}),
    (KatanaAdapter, "katana-1.1.0.jsonl", "api.example.test", {}),
    (JsluiceAdapter, "jsluice-urls-0.0.3.jsonl", "api.example.test", {}),
]


def envelope_for(adapter, target) -> ExecutionEnvelope:
    return ExecutionEnvelope.for_manifest(
        adapter.manifest, tenant_id="t", engagement_id="eng-1", scan_id="scan-1",
        stage_id="st", task_id=f"tk-{adapter.manifest.name}", target=target,
        scope_digest="d", idempotency_key=f"k-{adapter.manifest.name}",
    )


def run_pipeline():
    """Run every adapter over its fixture, normalizing into one asset view."""
    normalizer = Normalizer(scope=SCOPE, engagement_id="eng-1", scan_id="scan-1")
    assets: dict = {}
    observations = []
    rejections = []
    for factory, fixture_name, target, cfg in PIPELINE:
        adapter = factory(STUB, allow_unpinned=True, **cfg)
        env = envelope_for(adapter, target)
        lines = (FIXTURES / fixture_name).read_text(encoding="utf-8").strip().splitlines()
        events = [e for line in lines if (e := adapter.parse_line(line, env)) is not None]
        result = normalizer.normalize(events)
        merge_into(assets, result.assets)
        observations.extend(result.observations)
        rejections.extend(result.rejections)
    return assets, observations, rejections


def repo_with_engagement(tmp_path):
    repo = SqliteRepository(str(tmp_path / "pipeline.db"))
    repo.save_engagement(EngagementRecord(
        id="eng-1", authorization={"customer_id": "t"}, status="active",
        created_at=datetime.now(timezone.utc)))
    from aegis.api import scans

    repo.create_scan(scans.new_scan(tenant_id="t", engagement_id="eng-1", scan_id="scan-1"))
    return repo


# --- the pipeline ------------------------------------------------------------

def test_all_five_adapters_populate_one_asset_graph():
    assets, observations, _ = run_pipeline()
    kinds = {a.kind for a in assets.values()}
    # Domains from subfinder, URLs from gau, a service + technologies from the
    # probe, routes and parameters from katana/jsluice.
    assert {AssetKind.DOMAIN, AssetKind.URL, AssetKind.SERVICE,
            AssetKind.TECHNOLOGY, AssetKind.ROUTE, AssetKind.PARAMETER} <= kinds
    assert len(observations) >= len(assets)


def test_every_asset_carries_its_discovering_source():
    assets, _, _ = run_pipeline()
    assert all(a.sources for a in assets.values())
    all_sources = {s.split("/")[0] for a in assets.values() for s in a.sources}
    assert all_sources == {"subfinder", "gau", "http-probe", "katana", "jsluice"}


def test_provider_provenance_survives_into_the_graph():
    assets, _, _ = run_pipeline()
    domains = [a for a in assets.values() if a.kind is AssetKind.DOMAIN]
    # subfinder reported api.example.test via crtsh
    api = next(a for a in domains if a.asset_key.endswith("api.example.test"))
    assert any(s.startswith("subfinder/") for s in api.sources)


def test_the_same_route_from_two_tools_is_one_asset_with_both_sources():
    assets, observations, _ = run_pipeline()
    # katana crawled /v1/users and the JS references the same endpoint, so the two
    # tools must collapse to one route asset carrying both sources.
    route = assets["route:GET api.example.test/v1/users"]
    assert {s.split("/")[0] for s in route.sources} == {"katana", "jsluice"}
    assert route.observation_count == 2
    # ...and both underlying observations survive independently.
    seen = [o for o in observations if o.asset_key == route.asset_key]
    assert {o.source for o in seen} == {"katana", "jsluice"}


def test_out_of_scope_and_wildcard_never_enter_the_graph():
    assets, _, rejections = run_pipeline()
    keys = " ".join(assets)
    assert "other-domain.test" not in keys
    assert not any("*" in k for k in assets)
    # The adapters themselves suppressed these, so the normalizer saw clean input.
    assert all("other-domain" not in r.detail for r in rejections)


def test_no_active_payload_is_ever_emitted():
    """Every Phase 2 adapter stays at passive_discovery capability."""
    for adapter in discovery_adapters(allow_unpinned=True).values():
        assert adapter.manifest.capability_tier == "passive_discovery"
    # ...and only the probe/crawl stages may touch the target at all.
    profiles = {a.manifest.name: a.manifest.network_profile
                for a in discovery_adapters(allow_unpinned=True).values()}
    assert profiles["subfinder"] == profiles["gau"] == profiles["jsluice"] == "passive-provider"
    assert profiles["http-probe"] == profiles["katana"] == "target-observation"


def test_secret_candidates_do_not_become_assets():
    adapter = JsluiceAdapter(STUB, allow_unpinned=True, config=JsluiceConfig(mode="secrets"))
    env = envelope_for(adapter, "api.example.test")
    lines = (FIXTURES / "jsluice-secrets-0.0.3.jsonl").read_text(encoding="utf-8").strip().splitlines()
    events = [e for line in lines if (e := adapter.parse_line(line, env)) is not None]
    assert any(e.kind == EventKind.SECRET_CANDIDATE for e in events)

    result = Normalizer(scope=SCOPE, engagement_id="eng-1", scan_id="scan-1").normalize(events)
    # A candidate is a lead for the quarantine path, never an asset.
    assert result.assets == {}


# --- durability --------------------------------------------------------------

def test_pipeline_produces_a_durable_provenance_rich_snapshot(tmp_path):
    repo = repo_with_engagement(tmp_path)
    assets, observations, _ = run_pipeline()
    repo.record_observations(observations)
    repo.upsert_assets(assets.values())
    snapshot = new_snapshot(engagement_id="eng-1", scan_id="scan-1",
                            assets=list(assets.values()), complete=True)
    repo.save_snapshot(snapshot)
    repo.close()

    reopened = SqliteRepository(str(tmp_path / "pipeline.db"))
    stored = reopened.assets_for_engagement("eng-1")
    assert len(stored) == len(assets)
    assert all(a.sources for a in stored)                      # provenance persisted
    assert len(reopened.observations_for_scan("scan-1")) == len(observations)

    saved = reopened.snapshots_for_engagement("eng-1")[0]
    assert saved.complete is True and len(saved.entries) == len(assets)


@pytest.mark.parametrize("kind", [AssetKind.DOMAIN, AssetKind.URL, AssetKind.SERVICE,
                                  AssetKind.ROUTE, AssetKind.PARAMETER, AssetKind.TECHNOLOGY])
def test_each_asset_kind_is_queryable(tmp_path, kind):
    repo = repo_with_engagement(tmp_path)
    assets, observations, _ = run_pipeline()
    repo.record_observations(observations)
    repo.upsert_assets(assets.values())
    assert repo.assets_for_engagement("eng-1", kind=kind), f"no {kind.value} assets stored"
