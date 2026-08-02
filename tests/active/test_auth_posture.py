"""Authentication-posture differential analysis (Phase 3 extension).

Scenarios taken directly from real broken-access-control reports: one sibling
route left open while its twins enforce auth, and the 400-vs-401 "auth was never
evaluated" discriminator.
"""

from __future__ import annotations

from aegis.active import (
    AuthPosture,
    RouteAuthObservation,
    analyze_auth_differential,
    classify_posture,
)


def obs(path, status, *, method="GET", host="api.example.test", has_data=True):
    return RouteAuthObservation(method=method, path=path, host=host, status=status, has_data=has_data)


# --- posture classification --------------------------------------------------

def test_status_codes_map_to_postures():
    assert classify_posture(401) is AuthPosture.ENFORCED
    assert classify_posture(403) is AuthPosture.ENFORCED
    assert classify_posture(400) is AuthPosture.UNAUTH_VALIDATION
    assert classify_posture(422) is AuthPosture.UNAUTH_VALIDATION
    assert classify_posture(200) is AuthPosture.UNAUTH_DATA
    assert classify_posture(404) is AuthPosture.NOT_FOUND


# --- the dominant report pattern: one open sibling ---------------------------

def test_one_open_sibling_among_enforcing_routes_is_flagged():
    # /api/orders (401) vs /api/orders-feed (200) — the B2B order-book report.
    anomalies = analyze_auth_differential([
        obs("/api/orders", 401),
        obs("/api/orders/{id}", 401),
        obs("/api/orders-feed", 200),
    ])
    assert len(anomalies) == 1
    a = anomalies[0]
    assert a.path == "/api/orders-feed" and a.posture is AuthPosture.UNAUTH_DATA
    assert a.confidence >= 0.8 and a.siblings_enforcing == 2


def test_validation_error_unauth_is_flagged_as_auth_not_evaluated():
    # The healthcare/auto-lead pattern: a write route returns 400 (reached logic),
    # not 401 — proving the auth filter never ran.
    anomalies = analyze_auth_differential([
        obs("/booking/config", 401),
        obs("/booking/leads", 400, method="PUT"),
    ])
    assert len(anomalies) == 1
    assert anomalies[0].posture is AuthPosture.UNAUTH_VALIDATION
    assert "validation error" in anomalies[0].reason


def test_consistent_enforcement_raises_no_anomaly():
    anomalies = analyze_auth_differential([
        obs("/api/orders", 401), obs("/api/account", 401), obs("/api/products", 403)])
    assert anomalies == []


def test_absent_routes_are_not_anomalies():
    anomalies = analyze_auth_differential([obs("/api/orders", 401), obs("/api/missing", 404)])
    assert anomalies == []


# --- standalone sensitive exposure -------------------------------------------

def test_standalone_unauth_sensitive_route_is_flagged_at_lower_confidence():
    # No enforcing siblings, but an unauthenticated 200 on a sensitive path
    # (the driver-GPS / directory reports).
    anomalies = analyze_auth_differential([obs("/api/drivers/nearby", 200)])
    assert len(anomalies) == 1 and anomalies[0].confidence < 0.6


def test_public_paths_are_not_flagged():
    anomalies = analyze_auth_differential([
        obs("/api/account", 401), obs("/public/brochure", 200), obs("/health", 200)])
    assert anomalies == []


def test_non_sensitive_standalone_200_is_not_flagged():
    # A lone public-looking 200 with no enforcing siblings and no sensitive path
    # should not be a finding (keeps false positives down).
    assert analyze_auth_differential([obs("/api/catalog", 200)]) == []


# --- grouping ----------------------------------------------------------------

def test_id_bearing_siblings_group_together():
    # /api/orders/{id} and /api/orders/{id}/items are the same family; an open
    # /api/orders/export among them is flagged.
    anomalies = analyze_auth_differential([
        obs("/api/orders/1001", 401),
        obs("/api/orders/1002/items", 403),
        obs("/api/orders/export", 200),
    ])
    assert [a.path for a in anomalies] == ["/api/orders/export"]


def test_different_families_do_not_cross_contaminate():
    # An enforced /api/account family should not make an unauth /public route in a
    # different family look anomalous.
    anomalies = analyze_auth_differential([
        obs("/api/account/summary", 401),
        obs("/feed/articles", 200, host="cdn.example.test"),
    ])
    assert anomalies == []       # different host + family, non-sensitive
