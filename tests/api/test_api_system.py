from fastapi.testclient import TestClient

from aegis.api import ControlPlaneConfig, create_app


def test_root(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.json()["service"] == "aegis control plane"


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_readyz_ok(client):
    r = client.get("/readyz")
    assert r.status_code == 200
    assert r.json()["ready"] is True


def test_readyz_not_ready_without_signing_keys():
    cfg = ControlPlaneConfig(
        api_keys={}, signing_keys={}, require_signature=True, auth_enabled=False
    )
    c = TestClient(create_app(cfg))
    r = c.get("/readyz")
    assert r.status_code == 503
    assert r.json()["ready"] is False


def test_correlation_id_header_is_returned(client):
    r = client.get("/healthz")
    assert "X-Request-ID" in r.headers


def test_correlation_id_is_honoured(client):
    r = client.get("/healthz", headers={"X-Request-ID": "trace-abc"})
    assert r.headers["X-Request-ID"] == "trace-abc"
