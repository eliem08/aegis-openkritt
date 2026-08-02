import httpx

from aegis.detect import BflaDetector, DetectorContext, ErrorDisclosureDetector, Identity
from aegis.netgate import build_gated_client

PUBLIC = lambda h: ["93.184.216.34"]  # noqa: E731
LOW = Identity("user_low", {"Authorization": "Bearer LOW"})
ADMIN = Identity("admin", {"Authorization": "Bearer ADMIN"})


def gated(handler):
    return build_gated_client(["api.example.test"], inner=httpx.MockTransport(handler), resolver=PUBLIC)


def ctx(handler, **kw):
    kw.setdefault("identities", [LOW, ADMIN])
    return DetectorContext(base_url="https://api.example.test", client=gated(handler), **kw)


# --- BFLA ---

def test_bfla_detected_when_low_priv_reaches_admin_fn():
    def handler(request):
        if request.url.path == "/admin/export":
            return httpx.Response(200, text='{"all_users":[...],"admin":true}')
        return httpx.Response(404)

    det = BflaDetector([{"url": "/admin/export", "low_identity": "user_low", "signature": "all_users"}])
    res = det.run(ctx(handler))
    assert len(res.candidates) == 1
    assert res.candidates[0].cwe == "CWE-285"


def test_bfla_no_finding_when_forbidden():
    def handler(request):
        if request.headers.get("authorization") == "Bearer LOW":
            return httpx.Response(403)
        return httpx.Response(200, text='{"all_users":[]}')

    det = BflaDetector([{"url": "/admin/export", "low_identity": "user_low", "signature": "all_users"}])
    assert det.run(ctx(handler)).candidates == []


def test_bfla_not_applicable_without_config():
    assert not BflaDetector().applicable(ctx(lambda r: httpx.Response(404)))


# --- error disclosure ---

def test_error_disclosure_detected():
    def handler(request):
        return httpx.Response(500, text="Traceback (most recent call last):\n  File ...\nValueError")

    res = ErrorDisclosureDetector(paths=["/search"]).run(ctx(handler))
    assert len(res.candidates) == 1
    assert res.candidates[0].cwe == "CWE-209"


def test_no_error_disclosure_on_clean_response():
    def handler(request):
        return httpx.Response(400, text='{"error":"bad request"}')  # generic, no stack trace

    assert ErrorDisclosureDetector(paths=["/search"]).run(ctx(handler)).candidates == []
