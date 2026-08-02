"""Recon -> BOLA auto-wiring: discovered endpoints + operator seeds -> targets."""

import httpx

from aegis.detect import (
    BolaDetector,
    DetectorContext,
    Identity,
    ObjectSeed,
    ReconWorker,
    build_bola_objects,
    route_signature,
)
from aegis.model import Asset, AttackSurface, PlannedAction, Route
from aegis.netgate import build_gated_client
from aegis.orchestrator import WorkerContext

PUBLIC = lambda h: ["93.184.216.34"]  # noqa: E731


def gated(handler):
    return build_gated_client(["api.example.test"], inner=httpx.MockTransport(handler), resolver=PUBLIC)


def test_route_signature_normalises_id_segments():
    assert route_signature("/users/{id}") == route_signature("/users/1001") == "/users/*"
    assert route_signature("/orders/{oid}/items") == "/orders/*/items"
    assert route_signature("/about") == "/about"


def test_build_bola_objects_only_for_discovered_endpoints():
    surface = AttackSurface(assets=[Asset(host="api.example.test", routes=[
        Route(method="GET", path="/users/{id}"),
        Route(method="GET", path="/about"),
    ])])
    seeds = [
        ObjectSeed(route="/users/{id}", object_id="1001", owner="user_a", canary="CANARY-1"),
        ObjectSeed(route="/secret/{id}", object_id="9", owner="user_a", canary="CANARY-2"),  # not discovered
    ]
    objs = build_bola_objects(surface, seeds)
    assert len(objs) == 1
    assert objs[0].url == "/users/1001"
    assert objs[0].canary == "CANARY-1"


def test_recon_then_bola_end_to_end():
    # Vulnerable target: serves /users/1001 to any authenticated identity, and an
    # OpenAPI spec that exposes the /users/{id} endpoint for recon to find.
    def handler(request):
        p = request.url.path
        if p == "/openapi.json":
            return httpx.Response(200, json={"paths": {"/users/{id}": {"get": {}}}},
                                  headers={"content-type": "application/json"})
        if p == "/users/1001":
            return httpx.Response(200, text='{"canary":"CANARY-1"}')
        return httpx.Response(404)

    # 1) recon discovers the surface
    recon = ReconWorker(client_factory=lambda t: gated(handler))
    action = PlannedAction(target="api.example.test", action="passive_discovery", worker="recon")
    surface = recon.run(action, WorkerContext(engagement_id="e", surface=AttackSurface())).surface_delta
    assert route_signature("/users/1001") in {route_signature(r.path) for a in surface.assets for r in a.routes}

    # 2) operator seeds -> auto-wired BOLA objects
    seeds = [ObjectSeed(route="/users/{id}", object_id="1001", owner="user_a", canary="CANARY-1")]
    objects = build_bola_objects(surface, seeds)
    assert objects and objects[0].url == "/users/1001"

    # 3) BOLA detector runs against the discovered+seeded target -> finds the bug
    ctx = DetectorContext(
        base_url="https://api.example.test", client=gated(handler),
        identities=[Identity("user_a", {"Authorization": "Bearer A"}),
                    Identity("user_b", {"Authorization": "Bearer B"})],
    )
    result = BolaDetector(objects).run(ctx)
    assert len(result.candidates) == 1
    assert result.candidates[0].cwe == "CWE-639"
