"""Phase 3 completion gate — the guarded active pipeline against a local
authorized lab.

Proves, in-process (no binaries, no network): the pipeline finds seeded
vulnerabilities, stays within exact request/capability budgets, produces no
finding from unstable or truncated scans, and rejects unapproved templates,
payload modes, identities, and routes.
"""

from __future__ import annotations

import httpx
import pytest

from aegis.active import (
    DiscoveryConfig,
    EnumConfig,
    RouteSchema,
    RouteSpec,
    classify_candidate,
    passes_report_gate,
    plan_detectors,
    routes_from_assets,
    run_parameter_stage,
    run_route_stage,
)
from aegis.active.detectors import Seed
from aegis.adapters import EventKind, ExecutionEnvelope
from aegis.detect import BolaDetector, DetectorContext, Identity, ObjectRef
from aegis.gateway import GatewayConfig, NetworkProfile, ScopedExecutionGateway
from aegis.graph import AssetKind, Normalizer
from aegis.policy.scope import ScopeGuard
from tests.active.lab import CANARY, LabApp

HOST = "lab.example.test"
BASE = f"https://{HOST}"
RESOLVER = lambda h: ["93.184.216.34"]
IDENTITIES = [Identity("alice", {"X-Account": "alice"}), Identity("bob", {"X-Account": "bob"})]


def gateway(budget=None, scope=(HOST,)):
    return ScopedExecutionGateway(
        GatewayConfig(profile=NetworkProfile.TARGET_OBSERVATION,
                      scope=ScopeGuard(list(scope)), request_budget=budget),
        resolver=RESOLVER)


def envelope(target=HOST):
    from aegis.adapters import AdapterManifest

    m = AdapterManifest(name="active", version="1", executable_digest="x", license="MIT",
                        capability_tier="benign_request_mutation", input_schema_version=1,
                        output_schema_version=1, network_profile="target-observation")
    return ExecutionEnvelope.for_manifest(
        m, tenant_id="t", engagement_id="e", scan_id="s", stage_id="st", task_id="tk",
        target=target, scope_digest="d", idempotency_key="k")


def normalize(events):
    return Normalizer(scope=ScopeGuard([HOST]), engagement_id="e", scan_id="s").normalize(events)


def discover_graph(lab, gw):
    """Route + parameter discovery -> a merged asset view."""
    schema = RouteSchema([RouteSpec("GET", "/health"), RouteSpec("GET", "/users/{id}"),
                          RouteSpec("GET", "/orders/{id}"), RouteSpec("GET", "/search")])
    route_events = run_route_stage(envelope(), schema, gateway=gw, transport=lab.gateway_transport(),
                                   base_url=BASE, host=HOST, config=EnumConfig(canary_value="probe-canary"))
    param_events = run_parameter_stage(envelope(), ["debug", "q", "page", "id"], gateway=gw,
                                       transport=lab.gateway_transport(), base_url=f"{BASE}/search")
    assets = {}
    from aegis.graph import merge_into
    merge_into(assets, normalize(route_events).assets)
    merge_into(assets, normalize(param_events).assets)
    return assets, route_events, param_events


def run_bola(lab, objects, *, gate=None):
    client = httpx.Client(transport=lab.httpx_transport())
    ctx = DetectorContext(base_url=BASE, client=client, identities=IDENTITIES,
                          action="authenticated_testing", gate=gate)
    try:
        return BolaDetector(objects=objects).run(ctx)
    finally:
        client.close()


# --- the gate: seeded bugs are found ----------------------------------------

def test_pipeline_discovers_seeds_plans_and_confirms_a_bola_bug():
    lab = LabApp(bola_vulnerable=True)
    gw = gateway()

    assets, _, _ = discover_graph(lab, gw)
    # discovery populated the graph with routes and the hidden parameter
    kinds = {a.kind for a in assets.values()}
    assert AssetKind.ROUTE in kinds and AssetKind.PARAMETER in kinds
    assert any(a.attributes.get("name") == "debug" for a in assets.values()
               if a.kind is AssetKind.PARAMETER)

    # recon -> BOLA transition off the discovered graph + an owned seed
    routes = routes_from_assets(assets.values())
    seed = Seed(route="/users/{id}", object_id="1001", owner="alice", canary=CANARY, param="id")
    plan = plan_detectors(routes, seeds=[seed], identities=IDENTITIES)
    bola_task = plan.by_detector("bola")
    assert bola_task is not None

    # run the real BOLA detector against the lab
    objects = [ObjectRef(**o) for o in bola_task.config["objects"]]
    result = run_bola(lab, objects)
    assert result.candidates, "seeded cross-account read should be found"

    # candidate -> verified (differential owner/other evidence)
    candidate, evidence = result.candidates[0], result.evidence[0]
    assert classify_candidate(candidate, evidence) == "verified"
    assert CANARY in evidence.canary.value or evidence.canary.value == CANARY


def test_a_non_vulnerable_lab_yields_no_verified_bola_finding():
    lab = LabApp(bola_vulnerable=False)     # bob gets 403 on alice's object
    objects = [ObjectRef(url="/users/1001", owner="alice", canary=CANARY)]
    result = run_bola(lab, objects)
    assert result.candidates == []          # no cross-account read to confirm


# --- exact budgets + per-detector gating ------------------------------------

def test_request_accounting_is_exact_through_the_gateway():
    lab = LabApp()
    gw = gateway()
    run_parameter_stage(envelope(), ["debug", "q", "page"], gateway=gw,
                        transport=lab.gateway_transport(), base_url=f"{BASE}/search")
    # every probe: engine -> gateway -> lab, counted once at each layer
    assert gw.requests_made == lab.calls
    assert all(a.allowed for a in gw.audit_events())


def test_detector_requests_are_gated_by_the_detectors_action():
    lab = LabApp()
    seen = []
    gate = lambda action, url: (seen.append(action), True)[1]
    run_bola(lab, [ObjectRef(url="/users/1001", owner="alice", canary=CANARY)], gate=gate)
    assert seen and set(seen) == {"authenticated_testing"}   # BOLA's declared action


# --- no finding from unstable or truncated ----------------------------------

def test_unstable_target_produces_no_clean_result():
    lab = LabApp(unstable=True)
    gw = gateway()
    _, route_events, param_events = discover_graph(lab, gw)

    param_diag = [e for e in param_events if e.kind == EventKind.DIAGNOSTIC]
    assert any(d.data["code"] == "unstable_target" for d in param_diag)
    route_diag = [e for e in route_events if e.kind == EventKind.DIAGNOSTIC]
    assert any(d.data.get("health") in ("unstable", "quarantined") for d in route_diag)


def test_truncated_scan_is_incomplete_not_clean():
    lab = LabApp()
    gw = gateway(budget=4)                  # exhausts mid-scan
    events = run_parameter_stage(envelope(), [f"p{i}" for i in range(40)], gateway=gw,
                                 transport=lab.gateway_transport(), base_url=f"{BASE}/search")
    diags = [e for e in events if e.kind == EventKind.DIAGNOSTIC]
    assert diags[-1].data["code"] == "gateway_blocked"     # explicitly incomplete
    assert gw.requests_made == 4                            # never over budget


# --- rejects the unapproved -------------------------------------------------

def test_rejects_unapproved_route_out_of_scope():
    # A route on a host outside scope is gateway-blocked -> host quarantined.
    gw = gateway(scope=("other.example.test",))
    events = run_route_stage(envelope(), RouteSchema([RouteSpec("GET", "/health")]),
                             gateway=gw, transport=LabApp().gateway_transport(),
                             base_url=BASE, host=HOST)
    assert not any(e.kind == EventKind.ROUTE for e in events)


def test_rejects_unapproved_identity_for_bfla():
    routes = routes_from_assets(discover_graph(LabApp(), gateway())[0].values())
    from aegis.active import BflaEndpoint

    ep = BflaEndpoint(url="/admin", low_identity="nonexistent", signature="X")
    plan = plan_detectors(routes, identities=IDENTITIES, privileged_endpoints=[ep])
    assert not plan.has("bfla")             # missing identity -> inapplicable

def test_rejects_unapproved_template_and_payload_mode():
    from aegis.adapters import DalfoxAdapter, DalfoxConfig, DangerousModeNotAuthorized

    # blind XSS without an OAST endpoint is refused
    with pytest.raises(DangerousModeNotAuthorized):
        DalfoxAdapter("/opt/x", allow_unpinned=True, config=DalfoxConfig(blind=True))
    # (Nuclei's unapproved-template rejection is covered in test_nuclei.py; the
    # gate relies on that same manifest allowlist.)
