from __future__ import annotations

import base64
import time

from fastapi.testclient import TestClient

from aegis.egress import EgressClaims, EgressServiceConfig, create_egress_app, issue_token
from aegis.egress.app import UpstreamResponse

SECRET = "s" * 48
NOW = int(time.time())


class Budget:
    def __init__(self):
        self.connected = True
        self.counts = {}

    def incr_window(self, key, window):
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]


def claims(**overrides):
    values = dict(
        tenant_id="tenant-a", engagement_id="eng-1", profile="target-observation",
        method="GET", destination="https://in.example.test/start", issued_at=NOW,
        expires_at=NOW + 60, budget_id="budget-1", request_limit=3,
        scope=["in.example.test"],
    )
    values.update(overrides)
    return EgressClaims(**values)


def client(sender, *, budget=None, resolver=None):
    app = create_egress_app(
        EgressServiceConfig(SECRET), budget_backend=budget or Budget(),
        resolver=resolver or (lambda host: ["93.184.216.34"]), sender=sender,
    )
    return TestClient(app)


def auth(value):
    return {"Authorization": "Bearer " + issue_token(value, SECRET, now=NOW)}


def test_authorized_fetch_uses_pinned_ip_and_filters_headers():
    observed = {}

    def sender(method, url, pinned_ip, headers, body):
        observed.update(method=method, url=url, pinned_ip=pinned_ip, headers=headers, body=body)
        return UpstreamResponse(200, {"Content-Type": "text/plain", "Set-Cookie": "secret"}, b"ok")

    response = client(sender).post(
        "/v1/fetch", headers=auth(claims()),
        json={"method": "GET", "url": "https://in.example.test/start",
              "headers": {"Accept": "text/plain", "X-Unsafe": "drop"}},
    )
    assert response.status_code == 200
    assert observed == {"method": "GET", "url": "https://in.example.test/start",
                        "pinned_ip": "93.184.216.34", "headers": {"accept": "text/plain"}, "body": b""}
    assert response.json()["headers"] == {"content-type": "text/plain"}
    assert base64.b64decode(response.json()["body_base64"]) == b"ok"


def test_request_must_match_signed_method_and_destination():
    response = client(lambda *args: None).post(
        "/v1/fetch", headers=auth(claims()),
        json={"method": "GET", "url": "https://in.example.test/different"},
    )
    assert response.status_code == 403


def test_out_of_scope_and_private_resolution_are_blocked_before_sender():
    called = []
    sender = lambda *args: called.append(args)
    token = claims(destination="https://outside.test/")
    response = client(sender).post(
        "/v1/fetch", headers=auth(token), json={"method": "GET", "url": token.destination},
    )
    assert response.status_code == 403 and called == []
    response = client(sender, resolver=lambda host: ["127.0.0.1"]).post(
        "/v1/fetch", headers=auth(claims()),
        json={"method": "GET", "url": claims().destination},
    )
    assert response.status_code == 403 and called == []


def test_redirects_are_reauthorized_and_budgeted():
    budget = Budget()

    def sender(method, url, pinned_ip, headers, body):
        if url.endswith("/start"):
            return UpstreamResponse(302, {"Location": "/final"}, b"")
        return UpstreamResponse(200, {}, b"done")

    response = client(sender, budget=budget).post(
        "/v1/fetch", headers=auth(claims()),
        json={"method": "GET", "url": claims().destination},
    )
    assert response.status_code == 200
    assert response.json()["redirects"] == 1
    assert next(iter(budget.counts.values())) == 2


def test_redirect_out_of_scope_is_denied():
    def sender(*args):
        return UpstreamResponse(302, {"location": "https://outside.test/"}, b"")

    response = client(sender).post(
        "/v1/fetch", headers=auth(claims()),
        json={"method": "GET", "url": claims().destination},
    )
    assert response.status_code == 403


def test_global_budget_is_fail_closed():
    budget = Budget()
    budget.counts["egress-budget:tenant-a:eng-1:budget-1"] = 3
    response = client(lambda *args: UpstreamResponse(200, {}, b"ok"), budget=budget).post(
        "/v1/fetch", headers=auth(claims()),
        json={"method": "GET", "url": claims().destination},
    )
    assert response.status_code == 429


def test_bad_or_expired_tokens_are_unauthorized():
    response = client(lambda *args: None).post(
        "/v1/fetch", headers={"Authorization": "Bearer bad.token"},
        json={"method": "GET", "url": claims().destination},
    )
    assert response.status_code == 401
    expired = claims(issued_at=NOW - 60, expires_at=NOW - 1)
    token = issue_token(expired, SECRET, now=NOW - 30)
    response = client(lambda *args: None).post(
        "/v1/fetch", headers={"Authorization": "Bearer " + token},
        json={"method": "GET", "url": expired.destination},
    )
    assert response.status_code == 401


def test_health_fails_when_budget_backend_is_down():
    budget = Budget()
    budget.connected = False
    response = client(lambda *args: None, budget=budget).get("/healthz")
    assert response.status_code == 503
