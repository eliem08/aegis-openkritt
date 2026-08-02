"""Detector orchestration (Phase 3) — the recon->BOLA transition, target sets
from discovery, BFLA identity-pair gating, per-detector reservations, and the
candidate != verification gate.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from aegis.active import (
    DETECTOR_ACTIONS,
    BflaEndpoint,
    Route,
    Seed,
    classify_candidate,
    is_differential,
    passes_report_gate,
    plan_detectors,
    reserve_plan,
    routes_from_assets,
)
from aegis.api.persistence import SqliteRepository
from aegis.api.reservations import ReservationService
from aegis.api.store import EngagementRecord

IDS = ["alice", "bob"]                       # two researcher-owned accounts


def routes():
    return [
        Route("GET", "/users/{id}", "api.example.test"),
        Route("GET", "/orders/{orderId}", "api.example.test"),
        Route("GET", "/health", "api.example.test"),
    ]


def seed(route="/users/{id}", owner="alice"):
    return Seed(route=route, object_id="1001", owner=owner, canary="CANARY-alice", param="id")


# --- recon -> BOLA transition -----------------------------------------------

def test_owned_seed_on_a_discovered_route_queues_a_bola_task():
    plan = plan_detectors(routes(), seeds=[seed()], identities=IDS)
    bola = plan.by_detector("bola")
    assert bola is not None
    assert bola.action == "authenticated_testing"
    assert bola.config["objects"][0]["url"] == "/users/1001"    # concretized from the seed
    assert bola.config["objects"][0]["owner"] == "alice"


def test_seed_for_an_undiscovered_route_does_not_queue_bola():
    plan = plan_detectors(routes(), seeds=[seed(route="/admin/{id}")], identities=IDS)
    assert not plan.has("bola")
    assert "no owned seed matched" in plan.skipped["bola"]


def test_bola_needs_two_owned_identities():
    plan = plan_detectors(routes(), seeds=[seed()], identities=["alice"])
    assert not plan.has("bola") and "two owned identities" in plan.skipped["bola"]


def test_transition_reads_directly_from_the_asset_graph(tmp_path):
    # A real discovered graph -> routes_from_assets -> plan: no manual wiring.
    from aegis.adapters import EventKind
    from aegis.graph import AssetKind, Normalizer
    from aegis.policy.scope import ScopeGuard
    from tests.graph.test_graph import event

    events = [
        event(EventKind.ROUTE, {"method": "GET", "path": "/users/{id}",
                                "parameters": [{"name": "id", "location": "path"}]}),
    ]
    result = Normalizer(scope=ScopeGuard(["api.example.test"]),
                        engagement_id="e", scan_id="s").normalize(events)
    discovered = routes_from_assets(result.assets.values())
    assert any(r.id_bearing for r in discovered)

    plan = plan_detectors(discovered, seeds=[seed()], identities=IDS)
    assert plan.has("bola")


# --- explicit target sets from discovery -------------------------------------

def test_route_detectors_target_discovered_routes():
    plan = plan_detectors(routes(), identities=IDS)
    missing_auth = plan.by_detector("missing_auth")
    assert missing_auth is not None
    assert set(missing_auth.targets) == {"/users/{id}", "/orders/{orderId}", "/health"}


def test_detectors_are_skipped_when_no_route_evidence_exists():
    plan = plan_detectors([], identities=IDS)
    for detector in ("missing_auth", "exposed_files", "cors", "open_redirect", "error_disclosure"):
        assert not plan.has(detector)
        assert "hard-coded defaults are not used" in plan.skipped[detector]


def test_each_task_carries_its_detectors_declared_action():
    plan = plan_detectors(routes(), seeds=[seed()], identities=IDS)
    for task in plan.tasks:
        assert task.action == DETECTOR_ACTIONS[task.detector]
    assert plan.by_detector("cors").action == "benign_request_mutation"
    assert plan.by_detector("exposed_files").action == "passive_discovery"


# --- BFLA identity-pair gating ----------------------------------------------

def test_bfla_requires_a_resolvable_low_identity_and_discriminator():
    ep = BflaEndpoint(url="/admin/users", low_identity="alice", signature="ADMIN_PANEL")
    plan = plan_detectors(routes(), identities=IDS, privileged_endpoints=[ep])
    assert plan.has("bfla") and plan.by_detector("bfla").targets == ("/admin/users",)


def test_bfla_with_differential_pair_is_planned():
    ep = BflaEndpoint(url="/admin/users", low_identity="alice", elevated_identity="bob")
    assert plan_detectors(routes(), identities=IDS, privileged_endpoints=[ep]).has("bfla")


def test_bfla_missing_identity_is_inapplicable_not_weak():
    ep = BflaEndpoint(url="/admin/users", low_identity="ghost", signature="X")
    plan = plan_detectors(routes(), identities=IDS, privileged_endpoints=[ep])
    assert not plan.has("bfla") and "resolvable low identity" in plan.skipped["bfla"]


def test_bfla_without_a_discriminator_is_skipped():
    ep = BflaEndpoint(url="/admin/users", low_identity="alice")   # no signature, no elevated
    plan = plan_detectors(routes(), identities=IDS, privileged_endpoints=[ep])
    assert not plan.has("bfla")


# --- per-detector reservations ----------------------------------------------

def engagement_repo(tmp_path, sessions=50):
    repo = SqliteRepository(str(tmp_path / "det.db"))
    return repo


def eng(sessions=50, spend=1000.0):
    return SimpleNamespace(id="eng-1", authorization=SimpleNamespace(
        spend_budget=spend, rate_limits=SimpleNamespace(max_concurrent_sessions=sessions)))


def test_each_detector_reserves_its_own_action(tmp_path):
    repo = engagement_repo(tmp_path)
    svc = ReservationService(repo)
    plan = plan_detectors(routes(), seeds=[seed()], identities=IDS)

    reserved = reserve_plan(plan, svc, eng())
    # one reservation per detector task, each tagged with that detector's action
    assert set(reserved) == {t.detector for t in plan.tasks}
    for detector, (reservation, action) in reserved.items():
        assert reservation is not None and action == DETECTOR_ACTIONS[detector]
    # sessions were held per detector, independently
    _, sessions = svc.usage("eng-1")
    assert sessions == len(plan.tasks)


def test_a_detector_that_cannot_fit_the_cap_is_blocked_without_affecting_others(tmp_path):
    repo = engagement_repo(tmp_path)
    svc = ReservationService(repo)
    plan = plan_detectors(routes(), seeds=[seed()], identities=IDS)
    reserved = reserve_plan(plan, svc, eng(sessions=2))     # only two slots
    granted = [d for d, (r, _) in reserved.items() if r is not None]
    blocked = [d for d, (r, _) in reserved.items() if r is None]
    assert len(granted) == 2 and len(blocked) == len(plan.tasks) - 2


# --- candidate != verification ----------------------------------------------

def test_differential_evidence_is_verified():
    evidence = SimpleNamespace(steps=["baseline as owner", "probe as other"])
    assert is_differential(evidence)
    assert classify_candidate(object(), evidence) == "verified"


def test_single_observation_is_only_a_hypothesis():
    evidence = SimpleNamespace(steps=["single 200 response"])
    status = classify_candidate(object(), evidence)
    assert status == "hypothesis" and not passes_report_gate(status)


def test_a_second_independent_replay_promotes_a_hypothesis():
    evidence = SimpleNamespace(steps=["single 200 response"])
    replays = iter([True])
    status = classify_candidate(object(), evidence, replay=lambda c: next(replays))
    assert status == "verified" and passes_report_gate(status)


def test_a_failed_replay_leaves_it_a_hypothesis():
    evidence = SimpleNamespace(steps=["single 200 response"])
    status = classify_candidate(object(), evidence, replay=lambda c: False)
    assert status == "hypothesis"
