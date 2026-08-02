import httpx

from aegis.detect import ReconWorker, parse_openapi
from aegis.model import AttackSurface, PlannedAction
from aegis.netgate import build_gated_client
from aegis.orchestrator import WorkerContext

PUBLIC = lambda h: ["93.184.216.34"]  # noqa: E731


def gated(handler):
    return build_gated_client(["api.example.test"], inner=httpx.MockTransport(handler), resolver=PUBLIC)


def test_parse_openapi_paths_and_params():
    spec = {"paths": {
        "/users/{id}": {"get": {"parameters": [{"name": "id", "in": "path"}]}, "post": {}},
        "/search": {"get": {"parameters": [{"name": "q", "in": "query"}]}},
    }}
    routes = parse_openapi(spec)
    keys = {(r.method, r.path) for r in routes}
    assert keys == {("GET", "/users/{id}"), ("POST", "/users/{id}"), ("GET", "/search")}
    get_user = next(r for r in routes if r.path == "/users/{id}" and r.method == "GET")
    assert get_user.parameters[0].name == "id"


def test_recon_discovers_routes_from_all_sources():
    def handler(request):
        p = request.url.path
        if p == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nDisallow: /admin/\nDisallow: /internal/api")
        if p == "/sitemap.xml":
            return httpx.Response(200, text="<urlset><url><loc>https://api.example.test/pricing</loc></url></urlset>")
        if p == "/":
            return httpx.Response(200, text='<a href="/dashboard">x</a><script src="/app.js"></script>',
                                  headers={"server": "nginx/1.25", "x-powered-by": "Express"})
        if p == "/app.js":
            return httpx.Response(200, text='const u = fetch("/api/v1/orders"); go("/account/settings")')
        if p == "/openapi.json":
            return httpx.Response(200, json={"paths": {"/users/{id}": {"get": {}}}},
                                  headers={"content-type": "application/json"})
        return httpx.Response(404)

    worker = ReconWorker(client_factory=lambda t: gated(handler))
    action = PlannedAction(target="api.example.test", action="passive_discovery", worker="recon")
    res = worker.run(action, WorkerContext(engagement_id="e", surface=AttackSurface()))

    asset = res.surface_delta.get("api.example.test")
    paths = {r.path for r in asset.routes}
    assert "/admin/" in paths            # robots
    assert "/internal/api" in paths      # robots
    assert "/pricing" in paths           # sitemap
    assert "/dashboard" in paths         # home html
    assert "/api/v1/orders" in paths     # js
    assert "/users/{id}" in paths        # openapi spec
    assert "nginx/1.25" in asset.technologies
    assert "Express" in asset.technologies


def test_recon_handles_empty_target():
    worker = ReconWorker(client_factory=lambda t: gated(lambda r: httpx.Response(404)))
    action = PlannedAction(target="api.example.test", action="passive_discovery", worker="recon")
    res = worker.run(action, WorkerContext(engagement_id="e", surface=AttackSurface()))
    assert res.surface_delta.get("api.example.test") is not None  # empty but present
