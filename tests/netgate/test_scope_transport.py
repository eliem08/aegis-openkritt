import httpx
import pytest

from aegis.netgate import ScopeViolation, build_gated_client, is_blocked_ip

SCOPE = ["api.example.test", "*.example.test"]
PUBLIC = lambda host: ["93.184.216.34"]  # noqa: E731


def ok_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, text="ok")


def make(handler, **kw) -> httpx.Client:
    kw.setdefault("resolver", PUBLIC)
    return build_gated_client(SCOPE, inner=httpx.MockTransport(handler), **kw)


def test_in_scope_allowed():
    assert make(ok_handler).get("https://api.example.test/health").status_code == 200


def test_wildcard_subdomain_allowed():
    assert make(ok_handler).get("https://shop.example.test/").status_code == 200


def test_out_of_scope_blocked():
    with pytest.raises(ScopeViolation):
        make(ok_handler).get("https://evil.com/")


def test_redirect_out_of_scope_blocked():
    def handler(request):
        if request.url.host == "api.example.test":
            return httpx.Response(302, headers={"location": "https://evil.com/"})
        return httpx.Response(200)

    with pytest.raises(ScopeViolation):
        make(handler).get("https://api.example.test/go")


def test_redirect_in_scope_allowed():
    def handler(request):
        if request.url.path == "/go":
            return httpx.Response(302, headers={"location": "https://shop.example.test/dest"})
        return httpx.Response(200, text="dest")

    r = make(handler).get("https://api.example.test/go")
    assert r.status_code == 200 and r.text == "dest"


def test_private_ip_blocked():
    with pytest.raises(ScopeViolation):
        make(ok_handler, resolver=lambda h: ["10.0.0.5"]).get("https://api.example.test/")


def test_resolution_failure_fails_closed():
    def bad(host):
        raise OSError("nxdomain")

    with pytest.raises(ScopeViolation):
        make(ok_handler, resolver=bad).get("https://api.example.test/")


def test_block_private_ips_disabled():
    c = make(ok_handler, resolver=lambda h: ["10.0.0.5"], block_private_ips=False)
    assert c.get("https://api.example.test/").status_code == 200


def test_on_block_callback_records():
    seen = []
    c = make(ok_handler, on_block=lambda host, reason: seen.append((host, reason)))
    with pytest.raises(ScopeViolation):
        c.get("https://evil.com/")
    assert seen[0][0] == "evil.com"


@pytest.mark.parametrize(
    "ip,blocked",
    [
        ("10.0.0.1", True),
        ("127.0.0.1", True),
        ("169.254.1.1", True),
        ("192.168.1.1", True),
        ("172.16.5.4", True),
        ("::1", True),
        ("notanip", True),
        ("93.184.216.34", False),
        ("8.8.8.8", False),
    ],
)
def test_is_blocked_ip(ip, blocked):
    assert is_blocked_ip(ip) is blocked
