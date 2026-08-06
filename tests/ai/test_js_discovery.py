"""JS discovery front-end: authorization gate + scope confinement (fake fetcher, no net)."""

from __future__ import annotations

import pytest

from aegis.ai.js_discovery import DiscoveryError, FetchScope, discover_and_triage, fetch_js


def _fake(responses):
    """responses: {url: (status, final_host, content_type, text)}"""
    def fetcher(url, timeout, ua):
        if url not in responses:
            raise RuntimeError("network")
        return responses[url]
    return fetcher


def test_refuses_without_authorization():
    scope = FetchScope(urls=["https://example.com/app.js"], authorized=False)
    with pytest.raises(DiscoveryError, match="authorized"):
        fetch_js(scope, fetcher=_fake({}))


def test_fetches_authorized_js():
    url = "https://example.com/app.js"
    f = _fake({url: (200, "example.com", "application/javascript", "var k='ghp_x';")})
    out = fetch_js(FetchScope(urls=[url], authorized=True), fetcher=f)
    assert out == {url: "var k='ghp_x';"}


def test_drops_cross_host_redirect():
    url = "https://example.com/app.js"
    # served, but the response's final host is a DIFFERENT host -> scope must drop it
    f = _fake({url: (200, "evil.com", "application/javascript", "secret")})
    assert fetch_js(FetchScope(urls=[url], authorized=True), fetcher=f) == {}


def test_drops_non_js_and_non_200():
    js = "https://example.com/a.js"
    html = "https://example.com/page"          # not js, no .js suffix, html content-type
    bad = "https://example.com/b.js"            # 404
    f = _fake({
        js: (200, "example.com", "text/javascript", "ok"),
        html: (200, "example.com", "text/html", "<html>"),
        bad: (404, "example.com", "application/javascript", "nope"),
    })
    out = fetch_js(FetchScope(urls=[js, html, bad], authorized=True), fetcher=f)
    assert out == {js: "ok"}


def test_only_http_urls():
    f = _fake({})
    out = fetch_js(FetchScope(urls=["file:///etc/passwd", "ftp://x/y.js"], authorized=True), fetcher=f)
    assert out == {}


def test_discover_and_triage_end_to_end():
    url = "https://example.com/app.js"
    f = _fake({url: (200, "example.com", "application/javascript",
                     'const t="ghp_ABCdefGHIjklMNOpqrsTUVwxyz0123456789";')})

    class FakeClient:                              # deterministic triage, no network
        def complete_json(self, messages):
            return {"verdict": "secret", "severity": "high", "confidence": 0.9,
                    "likely_live": 0.8, "is_public_client_key": False, "reason": "PAT"}

    findings = discover_and_triage(FetchScope(urls=[url], authorized=True), FakeClient(), fetcher=f)
    assert findings and findings[0].kind == "github-token"
    assert findings[0].triage.verdict == "secret"
