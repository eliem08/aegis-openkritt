"""The review-console UI router: page shell + live/upload review models."""

from __future__ import annotations

import httpx
from fastapi.testclient import TestClient

from aegis.api import ControlPlaneConfig, create_app
from aegis.integrations import OpenKrittClient

EXPORT = {
    "vulnerabilities": [{
        "id": 1, "dedupe_is_canonical": True, "bounty_rank_impact_level": "critical",
        "json_answer": {"vulnerability_type": "Reentrancy", "file_path": "contracts/Vault.sol",
                        "line": 42, "summary": "reentrant withdraw", "explanation": "call before write",
                        "trigger_flow": "…", "malicious_input_example": "x", "malicious_actor": "any"},
    }]
}


def _app(config=None) -> TestClient:
    return TestClient(create_app(config or ControlPlaneConfig(auth_enabled=False, require_signature=False)))


def test_console_page_is_served_self_contained():
    r = _app().get("/ui")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    assert "review console" in r.text
    assert "http" not in r.text.split("<style>")[1].split("</style>")[0]  # no external asset URLs in CSS


def test_review_without_a_backend_reports_it():
    r = _app().get("/ui/review")
    assert r.status_code == 200
    body = r.json()
    assert body["items"] == [] and "No open·kritt backend" in body["note"]
    assert body["backend_connected"] is False


def test_review_from_uploaded_export():
    r = _app().post("/ui/review", json={"export": EXPORT})
    body = r.json()
    assert body["totals"]["candidates"] == 1
    assert body["items"][0]["source"] == "open-kritt"
    assert body["items"][0]["cwe"] == "CWE-841"


def test_review_live_from_connected_backend(monkeypatch):
    cfg = ControlPlaneConfig(auth_enabled=False, require_signature=False,
                             openkritt_url="http://okritt.local")

    def handler(req):
        assert req.url.path == "/api/scans/7/vulnerabilities"
        return httpx.Response(200, json=[{
            "vulnerability_type": "Missing access control", "file_path": "contracts/Vault.sol",
            "line": 55, "summary": "unguarded drain", "explanation": "no owner check",
            "dedupe": {"isCanonical": True}, "bountyRank": {"impactLevel": "high"},
        }])

    def fake_client():
        return OpenKrittClient("http://okritt.local",
                               client=httpx.Client(transport=httpx.MockTransport(handler)))

    app = create_app(cfg)
    app.state.config.build_openkritt_client = fake_client      # inject the mock-transport client
    client = TestClient(app)

    body = client.get("/ui/review", params={"scan": "7"}).json()
    assert body["backend_connected"] is True and body["scan_id"] == "7"
    assert body["totals"]["candidates"] == 1
    assert body["items"][0]["cwe"] == "CWE-284"


def test_review_degrades_when_backend_configured_but_unreachable():
    cfg = ControlPlaneConfig(auth_enabled=False, require_signature=False,
                             openkritt_url="http://127.0.0.1:3002")

    def down(req):
        raise httpx.ConnectError("connection refused", request=req)

    def fake_client():
        return OpenKrittClient("http://127.0.0.1:3002",
                               client=httpx.Client(transport=httpx.MockTransport(down)))

    app = create_app(cfg)
    app.state.config.build_openkritt_client = fake_client
    r = TestClient(app).get("/ui/review")
    assert r.status_code == 200                              # not a 500
    assert "not reachable" in r.json()["note"]
