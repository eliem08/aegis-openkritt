"""Wiring the new analyzers into detector-planning and the reporting/surface flow."""

from __future__ import annotations

from aegis.active import (
    RouteAuthObservation,
    Route,
    Seed,
    plan_detectors,
    surface_candidates,
)

IDS = ["alice", "bob"]
AWS = "AKIAIOSFODNN7EXAMPLE"


# --- planning: SSRF + GraphQL tasks -----------------------------------------

def test_ssrf_task_planned_when_url_parameters_exist():
    routes = [Route("GET", "/import", "api.example.test",
                    parameters=({"name": "webhook", "location": "query"},
                                {"name": "id", "location": "query"}))]
    plan = plan_detectors(routes, identities=IDS)
    ssrf = plan.by_detector("ssrf")
    assert ssrf is not None and ssrf.config["parameters"] == ["webhook"]
    assert ssrf.action == "benign_request_mutation"


def test_ssrf_skipped_without_url_parameters():
    routes = [Route("GET", "/users/{id}", "api.example.test",
                    parameters=({"name": "id", "location": "path"},))]
    plan = plan_detectors(routes, identities=IDS)
    assert not plan.has("ssrf") and "URL-accepting" in plan.skipped["ssrf"]


def test_graphql_task_planned_for_a_graphql_endpoint():
    routes = [Route("POST", "/graphql", "api.example.test"), Route("GET", "/health", "api.example.test")]
    plan = plan_detectors(routes, identities=IDS)
    gql = plan.by_detector("graphql")
    assert gql is not None and gql.targets == ("/graphql",)


def test_graphql_skipped_without_an_endpoint():
    plan = plan_detectors([Route("GET", "/health", "api.example.test")], identities=IDS)
    assert not plan.has("graphql")


# --- surfacing analytical findings into candidates ---------------------------

def test_hardening_finding_becomes_a_candidate():
    candidates = surface_candidates(hardening_responses=[{
        "url": "https://app.example.test/upload/x.svg",
        "headers": {"Content-Type": "image/svg+xml"}, "upload": True}])
    cwes = {c.cwe for c in candidates}
    assert "CWE-79" in cwes
    assert all(c.worker == "analyzer:hardening" for c in candidates)


def test_js_secret_becomes_a_candidate_without_the_raw_value():
    candidates = surface_candidates(
        scripts=[{"url": "https://app.example.test/app.js", "text": f'const t="{AWS}";'}],
        scope_hosts=["app.example.test"])
    secret = next(c for c in candidates if c.cwe == "CWE-798")
    assert "first-party" in secret.observed and AWS not in secret.observed
    assert secret.code_location.endswith(":1")


def test_client_script_finding_becomes_a_candidate():
    candidates = surface_candidates(
        scripts=[{"url": "https://app.example.test/a.js", "text": "opener.postMessage(m, '*');"}])
    assert any(c.cwe == "CWE-346" for c in candidates)


def test_auth_anomaly_becomes_a_candidate():
    obs = [RouteAuthObservation("GET", "/api/orders", "api.example.test", 401),
           RouteAuthObservation("GET", "/api/orders-feed", "api.example.test", 200)]
    candidates = surface_candidates(auth_observations=obs)
    anomaly = next(c for c in candidates if c.worker == "analyzer:auth_posture")
    assert anomaly.route == "/api/orders-feed" and anomaly.cwe == "CWE-306"


def test_no_artifacts_yields_no_candidates():
    assert surface_candidates() == []


def test_surfaced_items_are_candidates_pending_verification():
    from aegis.model import Candidate

    candidates = surface_candidates(hardening_responses=[{
        "url": "https://app.example.test/x", "headers": {"Content-Type": "text/html"}}])
    # A Candidate is a hypothesis by type — it becomes a Finding only after the
    # verification/replay step (candidate != verification).
    assert candidates and all(isinstance(c, Candidate) and c.evidence_id is None for c in candidates)
