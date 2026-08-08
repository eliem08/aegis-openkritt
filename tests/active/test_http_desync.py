from __future__ import annotations

from aegis.active import (
    DesyncFamily,
    DesyncObservation,
    analyze_desync_observations,
    plan_detectors,
)
from aegis.active.detectors import Route


def test_h2_downgrade_and_parser_signals_rank_candidate():
    candidates = analyze_desync_observations(
        [
            DesyncObservation(
                route="/api/upload",
                host="api.example",
                client_protocol="h2",
                upstream_protocol="h1",
                intermediary_chain=("cdn", "proxy", "app"),
                connection_reused=True,
                response_desync_signal=True,
                provenance="passive-fingerprint",
            )
        ]
    )
    assert candidates
    assert candidates[0].family is DesyncFamily.H2_DOWNGRADE
    assert candidates[0].confidence >= 0.8
    assert candidates[0].route == "/api/upload"


def test_length_ambiguity_creates_cl_te_and_te_cl_hypotheses():
    candidates = analyze_desync_observations(
        [
            DesyncObservation(
                route="/submit",
                has_content_length=True,
                has_transfer_encoding=True,
                intermediary_chain=("edge", "origin"),
            )
        ],
        min_confidence=0.4,
    )
    assert {candidate.family for candidate in candidates} == {
        DesyncFamily.CL_TE,
        DesyncFamily.TE_CL,
    }


def test_detector_planner_never_invents_route_from_desync_candidate():
    candidates = analyze_desync_observations(
        [
            DesyncObservation(
                route="/not-discovered",
                has_content_length=True,
                has_transfer_encoding=True,
                response_desync_signal=True,
            )
        ],
        min_confidence=0.4,
    )
    plan = plan_detectors(
        [Route("POST", "/known", "api.example")],
        enabled={"http_desync"},
        desync_candidates=candidates,
    )
    assert not plan.has("http_desync")
    assert "did not match a discovered route" in plan.skipped["http_desync"]


def test_detector_planner_queues_only_evidence_backed_discovered_route():
    candidates = analyze_desync_observations(
        [
            DesyncObservation(
                route="/known",
                host="api.example",
                client_protocol="h2",
                upstream_protocol="h1",
                intermediary_chain=("cdn", "proxy"),
                response_desync_signal=True,
            )
        ]
    )
    plan = plan_detectors(
        [Route("POST", "/known", "api.example")],
        enabled={"http_desync"},
        desync_candidates=candidates,
    )
    task = plan.by_detector("http_desync")
    assert task is not None
    assert task.targets == ("/known",)
    assert task.config["mode"] == "evidence_guided_validation"
    assert task.config["hypotheses"][0]["route"] == "/known"
