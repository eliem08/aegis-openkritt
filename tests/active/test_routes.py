"""Clean-room API route discovery (Phase 3).

The Aegis route schema is populated from OpenAPI + discovered routes, and the
enumerator confirms existence against a fake host: wildcard/catch-all baselines
suppress false positives, unhealthy hosts are quarantined, discovery uses a safe
method only, and everything is bounded.
"""

from __future__ import annotations

import pytest

from aegis.active.routes import (
    EnumConfig,
    HostHealth,
    RouteEnumerator,
    RouteRisk,
    RouteSchema,
    RouteSource,
    RouteSpec,
    ProbeResponse,
)

CFG = EnumConfig(canary_value="CANARY", wildcard_probes=3)

OPENAPI = {
    "paths": {
        "/users/{id}": {
            "parameters": [{"name": "trace", "in": "header"}],
            "get": {"parameters": [{"name": "fields", "in": "query"}]},
            "delete": {},
        },
        "/admin/reset": {
            "post": {"requestBody": {"content": {"application/json": {
                "schema": {"properties": {"confirm": {}, "token": {}}, "required": ["confirm"]}}}}},
        },
        "/health": {"get": {}},
    }
}


class FakeHost:
    """A synthetic host with a known set of existing paths."""

    def __init__(self, *, real=(), wildcard=False, distinct=(), unstable=False,
                 rate_limit=False, errors_after=None):
        self.real = set(real)
        self.wildcard = wildcard
        self.distinct = set(distinct)      # differ from the catch-all body
        self.unstable = unstable
        self.rate_limit = rate_limit
        self.errors_after = errors_after
        self.calls = 0
        self.methods_seen: list[str] = []
        self.paths_seen: list[str] = []

    def __call__(self, method: str, path: str) -> ProbeResponse:
        self.calls += 1
        self.methods_seen.append(method)
        self.paths_seen.append(path)
        if self.rate_limit:
            return ProbeResponse(status=429)
        if self.errors_after is not None and self.calls > self.errors_after:
            return ProbeResponse(status=500, error=True)
        if self.unstable:
            return ProbeResponse(status=200 if self.calls % 2 else 404, body="jitter")
        if self.wildcard:
            if path in self.distinct:
                return ProbeResponse(status=200, body="<html>a genuinely different page here</html>")
            return ProbeResponse(status=200, body="<html>catch all</html>")
        if path in self.real:
            return ProbeResponse(status=200, body=f"<html>real page for {path}</html>")
        return ProbeResponse(status=404, body="not found")


# --- schema ------------------------------------------------------------------

def test_openapi_populates_the_route_schema():
    schema = RouteSchema.from_openapi(OPENAPI)
    keys = {r.key for r in schema}
    assert "GET /users/{}" in keys and "DELETE /users/{}" in keys and "POST /admin/reset" in keys

    get_users = next(r for r in schema if r.key == "GET /users/{}")
    field_names = {f.name for f in get_users.fields}
    assert {"trace", "fields"} <= field_names          # shared + operation params
    assert RouteSource.OPENAPI.value in get_users.sources


def test_risk_annotations_are_derived():
    schema = RouteSchema.from_openapi(OPENAPI)
    delete = next(r for r in schema if r.key == "DELETE /users/{}")
    assert RouteRisk.STATE_CHANGING in delete.risks

    admin = next(r for r in schema if r.key == "POST /admin/reset")
    assert {RouteRisk.STATE_CHANGING, RouteRisk.ADMIN} <= admin.risks

    health = next(r for r in schema if r.key == "GET /health")
    assert health.risks == frozenset({RouteRisk.READ_ONLY})


def test_body_fields_and_content_type_are_captured():
    reset = next(r for r in RouteSchema.from_openapi(OPENAPI) if r.key == "POST /admin/reset")
    assert reset.content_type == "application/json"
    body = {f.name: f for f in reset.fields if f.location == "body"}
    assert set(body) == {"confirm", "token"} and body["confirm"].required


def test_discovered_and_openapi_routes_merge_with_both_sources():
    schema = RouteSchema.from_openapi(OPENAPI)
    schema.merge(RouteSchema.from_discovered([{"method": "GET", "path": "/users/{id}"}]))
    users = next(r for r in schema if r.key == "GET /users/{}")
    assert set(users.sources) == {RouteSource.OPENAPI.value, RouteSource.DISCOVERED.value}
    assert len(schema) == 4                             # merge did not create a duplicate


def test_template_paths_normalize_to_one_key():
    schema = RouteSchema([
        RouteSpec("GET", "/users/{id}"), RouteSpec("GET", "/users/{userId}/")])
    assert len(schema) == 1


# --- enumeration: not-found baseline -----------------------------------------

def test_existing_routes_are_confirmed_against_a_not_found_baseline():
    host = FakeHost(real={"/users/CANARY", "/health"})
    schema = RouteSchema.from_openapi(OPENAPI)
    result = RouteEnumerator(host, host="api.example.test", config=CFG).enumerate(schema)

    assert result.health is HostHealth.HEALTHY and result.complete
    assert result.present_paths == {"/users/{id}", "/health"}
    assert "/admin/reset" not in result.present_paths   # 404 -> suppressed


def test_discovery_uses_a_safe_method_even_for_state_changing_routes():
    host = FakeHost(real={"/users/CANARY"})
    schema = RouteSchema.from_openapi(OPENAPI)           # includes DELETE + POST
    RouteEnumerator(host, host="api.example.test", config=CFG).enumerate(schema)
    assert set(host.methods_seen) == {"GET"}            # never DELETE/POST on the wire


def test_state_changing_route_is_reported_with_its_real_method_and_risk():
    host = FakeHost(real={"/users/CANARY"})
    schema = RouteSchema.from_openapi(OPENAPI)
    result = RouteEnumerator(host, host="api.example.test", config=CFG).enumerate(schema)
    delete = next((r for r in result.routes if r.method == "DELETE"), None)
    assert delete is not None and delete.present
    assert "state_changing" in delete.risks


def test_one_probe_per_unique_path_regardless_of_method_count():
    host = FakeHost(real={"/users/CANARY"})
    schema = RouteSchema.from_openapi(OPENAPI)           # GET+DELETE share /users/{id}
    RouteEnumerator(host, host="api.example.test", config=CFG).enumerate(schema)
    # 3 baseline probes + 3 unique concretized paths (/users, /admin/reset, /health)
    assert host.calls == 6
    assert host.paths_seen.count("/users/CANARY") == 1


# --- enumeration: catch-all suppression --------------------------------------

def test_catch_all_host_suppresses_false_positives():
    host = FakeHost(wildcard=True)
    schema = RouteSchema.from_openapi(OPENAPI)
    result = RouteEnumerator(host, host="api.example.test", config=CFG).enumerate(schema)
    assert result.health is HostHealth.CATCH_ALL
    assert result.routes == [] and result.suppressed > 0   # nothing manufactured


def test_route_that_differs_from_catch_all_is_still_found():
    host = FakeHost(wildcard=True, distinct={"/health"})
    schema = RouteSchema.from_openapi(OPENAPI)
    result = RouteEnumerator(host, host="api.example.test", config=CFG).enumerate(schema)
    assert result.present_paths == {"/health"}          # only the genuinely different one


# --- enumeration: health + caps ----------------------------------------------

def test_rate_limited_host_is_quarantined_before_start():
    host = FakeHost(rate_limit=True)
    result = RouteEnumerator(host, host="api.example.test", config=CFG).enumerate(
        RouteSchema.from_openapi(OPENAPI))
    assert result.health is HostHealth.QUARANTINED
    assert not result.complete and result.reason == "host_unhealthy_before_start"


def test_host_is_quarantined_after_repeated_errors():
    # Healthy long enough to baseline, then errors flood in.
    host = FakeHost(real={"/users/CANARY"}, errors_after=3)
    cfg = EnumConfig(canary_value="CANARY", wildcard_probes=3, max_errors_per_host=2)
    many = RouteSchema([RouteSpec("GET", f"/r{i}") for i in range(20)])
    result = RouteEnumerator(host, host="api.example.test", config=cfg).enumerate(many)
    assert result.health is HostHealth.QUARANTINED and result.reason == "host_quarantined"
    assert not result.complete


def test_request_budget_stops_enumeration():
    host = FakeHost(real=set())
    cfg = EnumConfig(canary_value="CANARY", wildcard_probes=3, max_requests=6)
    many = RouteSchema([RouteSpec("GET", f"/r{i}") for i in range(50)])
    result = RouteEnumerator(host, host="api.example.test", config=cfg).enumerate(many)
    assert not result.complete and result.reason == "request_budget"
    assert result.requests <= 7


def test_unstable_host_yields_incomplete_not_clean():
    host = FakeHost(unstable=True)
    result = RouteEnumerator(host, host="api.example.test", config=CFG).enumerate(
        RouteSchema.from_openapi(OPENAPI))
    assert result.health is HostHealth.UNSTABLE and not result.complete
    assert result.reason == "unstable_host"
