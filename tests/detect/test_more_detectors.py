import httpx

from aegis.detect import CorsMisconfigDetector, DetectorContext, MissingAuthDetector
from aegis.netgate import build_gated_client

PUBLIC = lambda h: ["93.184.216.34"]  # noqa: E731
SCOPE = ["api.example.test"]


def gated(handler):
    return build_gated_client(SCOPE, inner=httpx.MockTransport(handler), resolver=PUBLIC)


def ctx(handler, **kw):
    return DetectorContext(base_url="https://api.example.test", client=gated(handler), **kw)


# --- CORS ---

def test_cors_credentialed_reflection_detected():
    def handler(request):
        origin = request.headers.get("origin", "")
        return httpx.Response(200, headers={
            "access-control-allow-origin": origin,
            "access-control-allow-credentials": "true",
        })

    res = CorsMisconfigDetector(paths=["/api"]).run(ctx(handler))
    assert len(res.candidates) == 1
    assert res.candidates[0].cwe == "CWE-942"


def test_cors_safe_when_origin_not_reflected():
    def handler(request):
        return httpx.Response(200, headers={
            "access-control-allow-origin": "https://trusted.example",
            "access-control-allow-credentials": "true",
        })

    assert CorsMisconfigDetector(paths=["/api"]).run(ctx(handler)).candidates == []


def test_cors_star_without_credentials_not_flagged():
    def handler(request):
        return httpx.Response(200, headers={"access-control-allow-origin": "*"})

    assert CorsMisconfigDetector(paths=["/api"]).run(ctx(handler)).candidates == []


# --- missing auth ---

def test_missing_auth_detected():
    def handler(request):
        return httpx.Response(200, text='{"users":[1,2],"secret":"x"}')

    det = MissingAuthDetector([{"url": "/admin/users", "signature": "users"}])
    res = det.run(ctx(handler))
    assert len(res.candidates) == 1
    assert res.candidates[0].cwe == "CWE-306"


def test_missing_auth_no_finding_when_protected():
    det = MissingAuthDetector([{"url": "/admin/users", "signature": "users"}])
    assert det.run(ctx(lambda r: httpx.Response(401))).candidates == []


def test_missing_auth_not_applicable_without_config():
    assert not MissingAuthDetector().applicable(ctx(lambda r: httpx.Response(404)))
