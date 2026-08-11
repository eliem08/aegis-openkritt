from __future__ import annotations

import base64
import time

from fastapi.testclient import TestClient

from aegis.egress import EgressClaims, EgressServiceConfig, create_egress_app, issue_token
from aegis.egress.app import UpstreamResponse, WebSocketResponse, _default_sender

SECRET = "s" * 48


def test_default_sender_closes_stream_without_response_context_manager(monkeypatch):
    class Response:
        status_code = 200
        headers = {"content-type": "text/plain"}
        closed = False

        def iter_bytes(self):
            yield b"ok"

        def close(self):
            self.closed = True

    response = Response()

    class Client:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def build_request(self, *_args, **_kwargs):
            return type("Request", (), {"extensions": {}})()

        def send(self, _request, *, stream):
            assert stream is True
            return response

    monkeypatch.setattr("aegis.egress.app.httpx.Client", Client)
    result = _default_sender("GET", "https://example.test/", "93.184.216.34", {}, b"")
    assert result.status_code == 200
    assert result.body == b"ok"
    assert response.closed


def _now() -> int:
    # computed at call time (not import) so tokens don't expire during a long full-suite run
    return int(time.time())


class Budget:
    def __init__(self):
        self.connected = True
        self.counts = {}

    def incr_window(self, key, window):
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]


def claims(**overrides):
    now = _now()
    values = dict(
        tenant_id="tenant-a", engagement_id="eng-1", profile="target-observation",
        method="GET", destination="https://in.example.test/start", issued_at=now,
        expires_at=now + 60, budget_id="budget-1", request_limit=3,
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
    return {"Authorization": "Bearer " + issue_token(value, SECRET, now=value.issued_at)}


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
    assert response.json()["pinned_ip"] == "93.184.216.34"
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
    now = _now()
    expired = claims(issued_at=now - 60, expires_at=now - 1)
    token = issue_token(expired, SECRET, now=now - 30)
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


def test_authorized_websocket_uses_pin_filters_headers_and_budgets_actions():
    observed = {}
    budget = Budget()

    def websocket_sender(url, pinned_ip, headers, messages, receive_limit, timeout_seconds):
        observed.update(
            url=url, pinned_ip=pinned_ip, headers=headers, messages=messages,
            receive_limit=receive_limit, timeout_seconds=timeout_seconds,
        )
        return WebSocketResponse(
            handshake_status=101, selected_protocol="events", messages=["ok"], close_code=1000,
        )

    app = create_egress_app(
        EgressServiceConfig(SECRET), budget_backend=budget,
        resolver=lambda _host: ["93.184.216.34"],
        sender=lambda *args: None, websocket_sender=websocket_sender,
    )
    test_client = TestClient(app)
    token = claims(
        destination="wss://in.example.test/events", request_limit=3,
        profile="target-mutation", allowed_methods=["GET"],
    )
    response = test_client.post(
        "/v1/websocket", headers=auth(token),
        json={
            "url": token.destination,
            "headers": {"Authorization": "Bearer controlled", "X-Unsafe": "drop"},
            "messages": ["subscribe", "state"],
            "receive_limit": 4,
        },
    )
    assert response.status_code == 200
    assert observed["pinned_ip"] == "93.184.216.34"
    assert observed["headers"] == {"authorization": "Bearer controlled"}
    assert observed["messages"] == ["subscribe", "state"]
    assert next(iter(budget.counts.values())) == 3


def test_websocket_destination_scope_and_action_budget_fail_closed():
    called = []

    def websocket_sender(*args):
        called.append(args)
        return WebSocketResponse(handshake_status=101)

    app = create_egress_app(
        EgressServiceConfig(SECRET), resolver=lambda _host: ["93.184.216.34"],
        sender=lambda *args: None, websocket_sender=websocket_sender,
    )
    test_client = TestClient(app)
    outside = claims(
        destination="wss://outside.test/events", request_limit=3,
        profile="target-mutation", allowed_methods=["GET"],
    )
    response = test_client.post(
        "/v1/websocket", headers=auth(outside),
        json={"url": outside.destination, "messages": ["subscribe"]},
    )
    assert response.status_code == 403 and called == []

    limited = claims(
        destination="wss://in.example.test/events", request_limit=2,
        profile="target-mutation", allowed_methods=["GET"],
    )
    response = test_client.post(
        "/v1/websocket", headers=auth(limited),
        json={"url": limited.destination, "messages": ["subscribe", "state"]},
    )
    assert response.status_code == 429 and called == []


def test_websocket_request_must_match_signed_destination():
    token = claims(
        destination="wss://in.example.test/events", request_limit=2,
        profile="target-mutation", allowed_methods=["GET"],
    )
    app = create_egress_app(
        EgressServiceConfig(SECRET), resolver=lambda _host: ["93.184.216.34"],
        sender=lambda *args: None,
        websocket_sender=lambda *args: WebSocketResponse(handshake_status=101),
    )
    response = TestClient(app).post(
        "/v1/websocket", headers=auth(token),
        json={"url": "wss://in.example.test/other", "messages": []},
    )
    assert response.status_code == 403


def test_protocol_endpoints_and_websocket_headers_cannot_be_confused_or_injected():
    ws_token = claims(
        destination="wss://in.example.test/events", request_limit=2,
        profile="target-mutation", allowed_methods=["GET"],
    )
    app = create_egress_app(
        EgressServiceConfig(SECRET), resolver=lambda _host: ["93.184.216.34"],
        sender=lambda *args: UpstreamResponse(200, {}, b"unexpected"),
        websocket_sender=lambda *args: WebSocketResponse(handshake_status=101),
    )
    test_client = TestClient(app)
    response = test_client.post(
        "/v1/fetch", headers=auth(ws_token),
        json={"method": "GET", "url": ws_token.destination},
    )
    assert response.status_code == 422

    http_token = claims(destination="https://in.example.test/events", request_limit=2)
    response = test_client.post(
        "/v1/websocket", headers=auth(http_token),
        json={"url": http_token.destination, "messages": []},
    )
    assert response.status_code == 422

    response = test_client.post(
        "/v1/websocket", headers=auth(ws_token),
        json={
            "url": ws_token.destination,
            "headers": {"authorization": "Bearer safe\r\nX-Injected: true"},
            "messages": [],
        },
    )
    assert response.status_code == 422
