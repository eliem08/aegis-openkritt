"""Stage-wiring (Phase 3): the clean-room engines run through the gateway.

Every probe is scope/method/budget-enforced by the real ScopedExecutionGateway;
results become PARAMETER/ROUTE events that normalize into the asset graph. An
out-of-scope or over-budget probe is stopped by the gateway, not the engine.
"""

from __future__ import annotations

import pytest

from aegis.active import (
    DiscoveryConfig,
    EnumConfig,
    RouteSchema,
    RouteSpec,
    TransportResponse,
    run_parameter_stage,
    run_route_stage,
)
from aegis.adapters import EventKind, ExecutionEnvelope
from aegis.gateway import GatewayConfig, NetworkProfile, ScopedExecutionGateway
from aegis.graph import AssetKind, Normalizer
from aegis.policy.scope import ScopeGuard

HOST = "api.example.test"
BASE = f"https://{HOST}"
# Stub resolver so tests never touch DNS; in-scope host resolves to a public IP.
RESOLVER = lambda host: ["93.184.216.34"]


def gateway(profile=NetworkProfile.TARGET_OBSERVATION, scope=(HOST,), budget=None):
    cfg = GatewayConfig(profile=profile, scope=ScopeGuard(list(scope)), request_budget=budget)
    return ScopedExecutionGateway(cfg, resolver=RESOLVER)


def envelope(cap="benign_request_mutation", profile="target-observation", target=HOST):
    from aegis.adapters import AdapterManifest

    m = AdapterManifest(name="active", version="1", executable_digest="x", license="MIT",
                        capability_tier=cap, input_schema_version=1, output_schema_version=1,
                        network_profile=profile)
    return ExecutionEnvelope.for_manifest(
        m, tenant_id="t", engagement_id="e", scan_id="s", stage_id="st", task_id="tk",
        target=target, scope_digest="d", idempotency_key="k")


class FakeSite:
    """Serves responses by path; reflects a query value for the 'debug' param."""

    def __init__(self, *, reflected_param="debug", real_routes=("/health",)):
        self.reflected_param = reflected_param
        self.real_routes = set(real_routes)
        self.calls = 0

    def __call__(self, method: str, url: str) -> TransportResponse:
        self.calls += 1
        from urllib.parse import parse_qs, urlsplit

        parts = urlsplit(url)
        body = "<html>base</html>"
        qs = parse_qs(parts.query)
        if self.reflected_param in qs:
            body += f"<echo>{qs[self.reflected_param][0]}</echo>"
        # route existence: a real path returns 200, else 404
        if parts.path and parts.path != "/":
            status = 200 if parts.path in self.real_routes else 404
        else:
            status = 200
        return TransportResponse(status=status, headers={"content-type": "text/html"}, body=body)


# --- parameter stage ---------------------------------------------------------

def test_parameter_stage_finds_a_param_through_the_gateway():
    gw = gateway()
    site = FakeSite(reflected_param="debug")
    events = run_parameter_stage(
        envelope(), ["debug", "q", "page", "id"], gateway=gw, transport=site, base_url=BASE)
    params = [e for e in events if e.kind == EventKind.PARAMETER]
    assert [p.data["name"] for p in params] == ["debug"]
    assert params[0].data["reflected"] is True
    # every probe went through the gateway and was audited
    assert gw.requests_made == site.calls and gw.requests_made > 0
    assert all(a.allowed for a in gw.audit_events())


def test_parameter_stage_events_normalize_into_the_graph():
    events = run_parameter_stage(
        envelope(), ["debug", "q"], gateway=gateway(), transport=FakeSite(), base_url=BASE)
    params = [e for e in events if e.kind == EventKind.PARAMETER]
    result = Normalizer(scope=ScopeGuard([HOST]), engagement_id="e", scan_id="s").normalize(params)
    assert any(a.kind is AssetKind.PARAMETER for a in result.assets.values())


def test_out_of_scope_base_url_is_blocked_by_the_gateway():
    # The gateway's scope only covers api.example.test; probing elsewhere is denied.
    events = run_parameter_stage(
        envelope(target="evil.other.test"), ["debug", "q"],
        gateway=gateway(scope=(HOST,)), transport=FakeSite(), base_url="https://evil.other.test")
    assert [e.kind for e in events] == [EventKind.DIAGNOSTIC]
    assert events[0].data["code"] == "gateway_blocked"


def test_request_budget_makes_the_stage_incomplete():
    gw = gateway(budget=3)                       # gateway allows only three requests
    events = run_parameter_stage(
        envelope(), [f"p{i}" for i in range(50)], gateway=gw, transport=FakeSite(), base_url=BASE)
    diags = [e for e in events if e.kind == EventKind.DIAGNOSTIC]
    assert diags and diags[-1].data["code"] == "gateway_blocked"
    assert gw.requests_made == 3                 # never exceeded the budget


# --- route stage -------------------------------------------------------------

def test_route_stage_confirms_routes_through_the_gateway():
    gw = gateway()
    site = FakeSite(real_routes=("/health", "/users/aegis-canary-7f3a"))
    schema = RouteSchema([RouteSpec("GET", "/health"), RouteSpec("GET", "/users/{id}"),
                          RouteSpec("GET", "/missing")])
    events = run_route_stage(envelope(), schema, gateway=gw, transport=site, base_url=BASE, host=HOST)
    routes = [e for e in events if e.kind == EventKind.ROUTE]
    assert {r.data["path"] for r in routes} == {"/health", "/users/{id}"}
    assert gw.requests_made > 0 and all(a.allowed for a in gw.audit_events())


def test_route_stage_events_normalize_into_the_graph():
    site = FakeSite(real_routes=("/health",))
    schema = RouteSchema([RouteSpec("GET", "/health")])
    events = run_route_stage(envelope(), schema, gateway=gateway(), transport=site,
                             base_url=BASE, host=HOST)
    routes = [e for e in events if e.kind == EventKind.ROUTE]
    result = Normalizer(scope=ScopeGuard([HOST]), engagement_id="e", scan_id="s").normalize(routes)
    assert any(a.kind is AssetKind.ROUTE for a in result.assets.values())


def test_route_stage_quarantines_a_host_the_gateway_blocks():
    # Scope excludes the host, so every probe is gateway-blocked -> unhealthy ->
    # the enumerator quarantines the host and reports incomplete.
    gw = gateway(scope=("other.example.test",))
    schema = RouteSchema([RouteSpec("GET", "/health")])
    events = run_route_stage(envelope(), schema, gateway=gw, transport=FakeSite(),
                             base_url=BASE, host=HOST)
    assert not any(e.kind == EventKind.ROUTE for e in events)
    diag = next(e for e in events if e.kind == EventKind.DIAGNOSTIC)
    assert diag.data["health"] == "quarantined"


# --- capability --------------------------------------------------------------

def test_a_state_changing_method_is_refused_by_the_gateway():
    # target-observation only permits safe methods; a POST probe is denied, so the
    # parameter stage cannot mutate state even if asked.
    gw = gateway(profile=NetworkProfile.TARGET_OBSERVATION)
    events = run_parameter_stage(
        envelope(), ["q"], gateway=gw, transport=FakeSite(), base_url=BASE,
        method="POST", config=DiscoveryConfig(method="POST", permitted_methods=("POST",)))
    assert [e.kind for e in events] == [EventKind.DIAGNOSTIC]
    assert events[0].data["code"] == "gateway_blocked"
