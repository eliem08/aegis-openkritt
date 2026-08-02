"""Identifier enumeration-risk analysis + BOLA planning integration.

Driven by real IDOR reports where a sequential id turns one bug into mass
exposure: a BOLA candidate on a consecutive-integer id must be flagged enumerable,
while one on a UUID must not.
"""

from __future__ import annotations

from aegis.active import (
    IdentifierKind,
    Route,
    Seed,
    analyze_identifiers,
    plan_detectors,
)

IDS = ["alice", "bob"]


# --- identifier analysis -----------------------------------------------------

def test_consecutive_integers_are_trivially_enumerable():
    p = analyze_identifiers(["1001", "1002", "1003", "1004"])
    assert p.kind is IdentifierKind.SEQUENTIAL_INT and p.enumerable
    assert p.enumeration_risk > 0.9


def test_near_sequential_integers_are_enumerable():
    p = analyze_identifiers(["500", "512", "540", "561"])
    assert p.kind is IdentifierKind.SEQUENTIAL_INT and p.enumerable


def test_small_integers_are_enumerable():
    p = analyze_identifiers(["7", "42", "9001"])
    assert p.kind is IdentifierKind.SMALL_INT and p.enumerable


def test_uuids_are_not_enumerable():
    p = analyze_identifiers([
        "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "9c858901-8a57-4791-81fe-4c455b099bc9"])
    assert p.kind is IdentifierKind.UUID and not p.enumerable
    assert p.enumeration_risk < 0.2


def test_high_entropy_tokens_are_not_enumerable():
    p = analyze_identifiers(["Zx9Kd8fQ2mNpW4vT", "aB3kL0zR7yH2wQ9m"])
    assert p.kind is IdentifierKind.HIGH_ENTROPY and not p.enumerable


def test_timestamp_like_ids_are_partially_predictable():
    p = analyze_identifiers(["1700000000", "1700000500"])
    assert p.kind is IdentifierKind.TIMESTAMP and not p.enumerable


def test_no_samples_is_opaque_zero_risk():
    p = analyze_identifiers([])
    assert p.enumeration_risk == 0.0 and p.samples == 0


# --- BOLA planning integration ----------------------------------------------

def routes():
    return [Route("GET", "/users/{id}", "api.example.test")]


def seed(object_id="1001"):
    return Seed(route="/users/{id}", object_id=object_id, owner="alice", canary="C", param="id")


def test_bola_task_is_flagged_enumerable_for_sequential_ids():
    plan = plan_detectors(routes(), seeds=[seed()], identities=IDS,
                          identifier_samples={"/users/{id}": ["1001", "1002", "1003"]})
    bola = plan.by_detector("bola")
    assert bola.config["enumerable"] is True
    assert bola.config["identifier_kind"] == "sequential_int"
    assert bola.config["enumeration_risk"] > 0.9


def test_bola_task_is_not_flagged_enumerable_for_uuids():
    samples = {"/users/{id}": ["3f2504e0-4f89-41d3-9a0c-0305e82c3301",
                               "9c858901-8a57-4791-81fe-4c455b099bc9"]}
    plan = plan_detectors(routes(), seeds=[seed(object_id="3f2504e0-4f89-41d3-9a0c-0305e82c3301")],
                          identities=IDS, identifier_samples=samples)
    bola = plan.by_detector("bola")
    assert bola.config["enumerable"] is False


def test_bola_planning_without_samples_is_unchanged():
    plan = plan_detectors(routes(), seeds=[seed()], identities=IDS)
    bola = plan.by_detector("bola")
    # the seed id alone (a small int) still yields a risk signal, but no crash
    assert "objects" in bola.config
