"""The asset graph lands durably, and a scan populates it end-to-end (Phase 2).

Observations are append-only and keep provenance across restarts; assets merge
into one derived row; snapshots record what a scan saw.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

from aegis.adapters import FakeDiscoveryAdapter
from aegis.api.persistence import SqliteRepository
from aegis.api.reservations import ReservationService
from aegis.api.store import EngagementRecord
from aegis.graph import Asset, AssetKind, Normalizer, domain_key, new_snapshot
from aegis.policy.scope import ScopeGuard
from aegis.scheduler import ScanConfig, ScanCoordinator, StageSpec, TaskSpec

from tests.graph.test_graph import NOW, event, EventKind  # shared fixtures

SCOPE = ScopeGuard(["api.example.test", "secret.example.test"])


def repo_with_engagement(tmp_path, name="graph.db", eid="eng-1"):
    repo = SqliteRepository(str(tmp_path / name))
    repo.save_engagement(EngagementRecord(
        id=eid, authorization={"customer_id": "t"}, status="active",
        created_at=datetime.now(timezone.utc)))
    return repo


def seeded_scan(repo, scan_id="scan-1"):
    from aegis.api import scans as scan_model

    scan = scan_model.new_scan(tenant_id="t", engagement_id="eng-1", scan_id=scan_id)
    repo.create_scan(scan)
    return scan


def normalize(scan_id="scan-1"):
    return Normalizer(scope=SCOPE, engagement_id="eng-1", scan_id=scan_id)


# --- durable round trip ------------------------------------------------------

def test_observations_and_assets_round_trip(tmp_path):
    repo = repo_with_engagement(tmp_path)
    seeded_scan(repo)
    result = normalize().normalize([
        event(EventKind.ASSET, {"identifier": "api.example.test", "asset_type": "domain",
                                "provider": "crtsh"}, source="subfinder"),
    ])
    repo.record_observations(result.observations)
    repo.upsert_assets(result.assets.values())

    assets = repo.assets_for_engagement("eng-1")
    assert len(assets) == 1 and assets[0].kind is AssetKind.DOMAIN
    assert assets[0].sources == ["subfinder/crtsh"]

    obs = repo.observations_for_asset("eng-1", domain_key("api.example.test"))
    assert len(obs) == 1 and obs[0].provider == "crtsh" and obs[0].observed_at == NOW


def test_multi_source_merge_is_one_asset_with_both_provenances(tmp_path):
    repo = repo_with_engagement(tmp_path)
    seeded_scan(repo)
    for source, provider in (("subfinder", "crtsh"), ("gau", "wayback")):
        r = normalize().normalize([
            event(EventKind.ASSET, {"identifier": "api.example.test", "asset_type": "domain",
                                    "provider": provider}, source=source),
        ])
        repo.record_observations(r.observations)
        repo.upsert_assets(r.assets.values())

    assets = repo.assets_for_engagement("eng-1")
    assert len(assets) == 1                                   # deduplicated
    assert assets[0].sources == ["gau/wayback", "subfinder/crtsh"]
    assert assets[0].observation_count == 2
    assert len(repo.observations_for_asset("eng-1", assets[0].asset_key)) == 2  # provenance kept


def test_graph_survives_a_restart(tmp_path):
    repo = repo_with_engagement(tmp_path)
    seeded_scan(repo)
    r = normalize().normalize([
        event(EventKind.ASSET, {"identifier": "api.example.test", "asset_type": "domain"})])
    repo.record_observations(r.observations)
    repo.upsert_assets(r.assets.values())
    repo.close()

    reopened = SqliteRepository(str(tmp_path / "graph.db"))
    assert len(reopened.assets_for_engagement("eng-1")) == 1
    assert len(reopened.observations_for_scan("scan-1")) == 1


def test_snapshots_persist_and_order_by_creation(tmp_path):
    repo = repo_with_engagement(tmp_path)
    seeded_scan(repo)
    a = Asset(engagement_id="eng-1", asset_key="domain:api.example.test", kind=AssetKind.DOMAIN,
              first_seen=NOW, last_seen=NOW)
    repo.save_snapshot(new_snapshot(engagement_id="eng-1", scan_id="scan-1", assets=[a], complete=True))
    repo.save_snapshot(new_snapshot(engagement_id="eng-1", scan_id="scan-1", assets=[], complete=False))

    saved = repo.snapshots_for_engagement("eng-1")
    assert len(saved) == 2
    assert saved[0].complete is True and saved[0].keys == {"domain:api.example.test"}
    assert saved[1].complete is False


def test_assets_can_be_filtered_by_kind(tmp_path):
    repo = repo_with_engagement(tmp_path)
    seeded_scan(repo)
    r = normalize().normalize([
        event(EventKind.ASSET, {"identifier": "api.example.test", "asset_type": "domain"}),
        event(EventKind.TECHNOLOGY, {"name": "nginx"}),
    ])
    repo.record_observations(r.observations)
    repo.upsert_assets(r.assets.values())
    assert len(repo.assets_for_engagement("eng-1", kind=AssetKind.TECHNOLOGY)) == 1


# --- end to end through the coordinator --------------------------------------

def coordinator(repo, targets=("api.example.test",)):
    return ScanCoordinator(
        repository=repo, reservations=ReservationService(repo),
        adapters={"fake-discovery": FakeDiscoveryAdapter()},
        config=ScanConfig(tenant_id="t", engagement_id="eng-1", scope_targets=tuple(targets)),
    )


def test_a_scan_populates_a_durable_snapshot(tmp_path):
    repo = repo_with_engagement(tmp_path)
    coord = coordinator(repo)
    scan_id = coord.plan_scan(
        [StageSpec("recon", "discovery")],
        [TaskSpec("fake-discovery", "api.example.test", "recon")],
    )
    steps = coord.run_scan(scan_id)
    assert steps[0].outcome == "succeeded"
    assert steps[0].assets > 0 and steps[0].rejected == 0

    # The fake tool emits an asset, two routes (one with a parameter), and a technology.
    kinds = sorted(a.kind.value for a in repo.assets_for_engagement("eng-1"))
    assert kinds == ["parameter", "route", "route", "technology", "url"]

    snapshot = coord.snapshot_scan(scan_id)
    assert snapshot.complete is True
    assert len(snapshot.entries) == len(repo.assets_for_engagement("eng-1"))
    assert repo.snapshots_for_engagement("eng-1")[0].snapshot_id == snapshot.snapshot_id


def test_quarantined_scan_yields_an_incomplete_snapshot(tmp_path):
    repo = repo_with_engagement(tmp_path)
    coord = coordinator(repo, targets=("secret.example.test",))
    scan_id = coord.plan_scan(
        [StageSpec("recon", "discovery")],
        [TaskSpec("fake-discovery", "secret.example.test", "recon")],
    )
    steps = coord.run_scan(scan_id)
    assert steps[0].outcome == "quarantined"

    # Quarantined output never reaches the graph...
    assert repo.assets_for_engagement("eng-1") == []
    # ...and the snapshot records partial coverage, so nothing can be called removed.
    assert coord.snapshot_scan(scan_id).complete is False


def test_out_of_scope_emissions_are_counted_not_stored(tmp_path):
    repo = repo_with_engagement(tmp_path)
    # The task target is authorized, but the graph scope is narrower than what the
    # tool reports, so its emissions must be rejected rather than persisted.
    coord = ScanCoordinator(
        repository=repo, reservations=ReservationService(repo),
        adapters={"fake-discovery": FakeDiscoveryAdapter()},
        config=ScanConfig(tenant_id="t", engagement_id="eng-1", scope_targets=("other.example.test",)),
    )
    scan_id = coord.plan_scan(
        [StageSpec("recon", "discovery")],
        [TaskSpec("fake-discovery", "api.example.test", "recon")],
    )
    steps = coord.run_scan(scan_id)
    assert steps[0].outcome == "succeeded"
    assert steps[0].assets == 0 and steps[0].rejected > 0
    assert repo.assets_for_engagement("eng-1") == []


# --- postgres parity (gated) -------------------------------------------------

DSN = os.environ.get("AEGIS_TEST_POSTGRES_DSN")


@pytest.mark.skipif(not DSN, reason="set AEGIS_TEST_POSTGRES_DSN to run")
def test_graph_round_trip_on_postgres():
    pytest.importorskip("psycopg")
    from aegis.api.postgres import PostgresRepository

    repo = PostgresRepository(DSN)
    repo._exec(
        "TRUNCATE engagements, grants, audit, kill_state, spend, reservations, scan_runs, "
        "stage_runs, task_runs, task_leases, artifacts, observations, assets, asset_snapshots CASCADE"
    )
    try:
        repo.save_engagement(EngagementRecord(
            id="eng-1", authorization={"customer_id": "t"}, status="active",
            created_at=datetime.now(timezone.utc)))
        coord = coordinator(repo)
        scan_id = coord.plan_scan(
            [StageSpec("recon", "discovery")],
            [TaskSpec("fake-discovery", "api.example.test", "recon")],
        )
        steps = coord.run_scan(scan_id)
        assert steps[0].outcome == "succeeded" and steps[0].assets > 0

        # merge a second source into the same domain asset
        r = normalize(scan_id).normalize([
            event(EventKind.ASSET, {"identifier": "api.example.test", "asset_type": "domain",
                                    "provider": "crtsh"}, source="subfinder"),
        ])
        repo.record_observations(r.observations)
        repo.upsert_assets(r.assets.values())
        merged = [a for a in repo.assets_for_engagement("eng-1") if a.kind is AssetKind.DOMAIN]
        assert len(merged) == 1 and "subfinder/crtsh" in merged[0].sources

        snapshot = coord.snapshot_scan(scan_id)
        assert repo.snapshots_for_engagement("eng-1")[-1].snapshot_id == snapshot.snapshot_id
    finally:
        repo.close()
