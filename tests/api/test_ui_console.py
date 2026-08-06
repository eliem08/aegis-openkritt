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
    assert "automatic code validation" in r.text
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


def test_feedback_is_recorded_and_reranks_the_upload_console():
    client = _app()
    # A noisy detector's finding, surfaced from an upload.
    export = {"vulnerabilities": [{"id": 1, "dedupe_is_canonical": True,
              "bounty_rank_impact_level": "critical",
              "json_answer": {"vulnerability_type": "Reentrancy", "file_path": "V.sol", "line": 1,
                              "summary": "s", "explanation": "e", "trigger_flow": "t",
                              "malicious_input_example": "x", "malicious_actor": "a"}}]}
    before = client.post("/ui/review", json={"export": export}).json()
    assert "learned_prior" not in before["items"][0] or before["items"][0].get("learned_prior") is None \
        or before["items"][0]["learned_prior"] == 0.5

    # Teach the loop this detector+CWE is usually a false positive.
    for _ in range(6):
        r = client.post("/ui/feedback", json={
            "detector": "integration:openkritt", "cwe": "CWE-841", "verdict": "false_positive"})
    assert r.json()["recorded"] == 6
    assert r.json()["learned_prior"] < 0.3

    after = client.post("/ui/review", json={"export": export}).json()
    assert after["items"][0]["learned_prior"] < 0.3      # calibration now applied


def test_feedback_rejects_a_bad_verdict():
    r = _app().post("/ui/feedback", json={"detector": "d", "cwe": "CWE-1", "verdict": "bogus"})
    assert "error" in r.json()


def test_hackerone_sync_folds_report_outcomes_into_the_loop(monkeypatch):
    app = create_app(ControlPlaneConfig(auth_enabled=False, require_signature=False))
    client = TestClient(app)

    # 1) link a submitted report to the finding it came from
    assert client.post("/ui/submission", json={
        "report_id": "5551", "detector": "integration:openkritt", "cwe": "CWE-841"}).json()["linked"] == "5551"

    # 2) HackerOne says it resolved -> confirmed. Stub the client's reports fetch.
    import aegis.ingest.hackerone as h1mod

    class FakeH1:
        @classmethod
        def from_env(cls, *a, **k):
            return cls()

        def list_my_reports(self):
            return [{"id": "5551", "attributes": {"state": "resolved"}}]

        def close(self):
            pass

    monkeypatch.setattr(h1mod, "HackerOneClient", FakeH1)

    body = client.post("/ui/hackerone-sync").json()
    assert body["recorded"] == 1 and body["by_verdict"] == {"confirmed": 1}

    # the confirmed outcome now lifts that detector's learned prior
    from aegis.learn import Calibration
    cal = Calibration.from_outcomes(app.state.outcomes.all())
    assert cal.prior(detector="integration:openkritt") > 0.5


def test_hackerone_sync_reports_missing_credentials(monkeypatch):
    monkeypatch.delenv("HACKERONE_API_USERNAME", raising=False)
    monkeypatch.delenv("HACKERONE_API_TOKEN", raising=False)
    body = _app().post("/ui/hackerone-sync").json()
    # no HACKERONE creds -> a clear error, not a crash or a network call
    assert "error" in body and "HackerOne" in body["error"]


def test_hunt_endpoint_requires_a_backend():
    body = _app().post("/ui/hunt", json={}).json()
    assert "error" in body and "open·kritt" in body["error"]


def test_hunt_endpoint_dry_run_plans_without_launching(monkeypatch):
    cfg = ControlPlaneConfig(auth_enabled=False, require_signature=False,
                             openkritt_url="http://okritt.local")

    class FakeH1:
        @classmethod
        def from_env(cls, *a, **k): return cls()
        def list_programs(self): return [{"attributes": {"handle": "acme"}}]
        def get_program(self, h): return {"data": {"attributes": {"handle": h, "policy": ""}}}
        def get_structured_scopes(self, h):
            return [{"attributes": {"asset_type": "SOURCE_CODE",
                     "asset_identifier": "https://github.com/acme/api", "eligible_for_submission": True,
                     "eligible_for_bounty": True, "max_severity": "high"}}]
        def list_my_reports(self): return []
        def close(self): pass

    class FakeOK:
        def list_scans(self): return []
        def create_scan(self, p): raise AssertionError("dry-run must not launch")
        def import_candidates(self, s, **k): return []
        def close(self): pass

    import aegis.ingest.hackerone as h1mod
    monkeypatch.setattr(h1mod, "HackerOneClient", FakeH1)
    app = create_app(cfg)
    app.state.config.build_openkritt_client = lambda: FakeOK()

    body = TestClient(app).post("/ui/hunt", json={}).json()      # dry-run (not armed)
    assert body["dry_run"] is True and body["repos_in_scope"] == 1
    assert body["scans_launched_this_cycle"] == 0


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



def test_latest_deepseek_model_downgrades_example_only_confirmation():
    from aegis.ai.report_validation import _review_model

    report = {
        "scan": {"id": "unit"},
        "vulnerabilities": [{
            "dedupe_is_canonical": True,
            "confidence": 0.9,
            "json_answer": {
                "vulnerability_type": "CWE-754",
                "file_path": "src/examples/Wrapper.sol",
                "line": 12,
                "summary": "ignored hook failure",
                "explanation": "hook result is unchecked",
                "trigger_flow": "owner calls relay",
                "malicious_input_example": "",
                "malicious_actor": "untrusted hook",
                "severity": "high",
            },
            "validation": {
                "verdict": "confirmed",
                "reason": "exact source quote matched",
                "confidence": 0.95,
                "anchors": [],
                "verification_test": "forge test",
            },
        }],
    }

    model = _review_model(report)

    assert model["totals"]["confirmed"] == 0
    assert model["totals"]["unresolved"] == 1
    assert "Example-only source is not report-ready" in model["items"][0]["validation_reason"]
