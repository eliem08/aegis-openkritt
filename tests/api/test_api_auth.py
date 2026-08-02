from fastapi.testclient import TestClient

from aegis.api import ControlPlaneConfig, create_app


def test_missing_token_401(client):
    assert client.get("/engagements").status_code == 401


def test_invalid_token_401(client):
    assert client.get("/engagements", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_agent_can_read(client, agent_headers):
    assert client.get("/engagements", headers=agent_headers).status_code == 200


def test_agent_forbidden_on_operator_endpoint(client, agent_headers, make_signed_auth):
    # Valid body, so a 403 (role) is what we're isolating — not a 422.
    r = client.post("/engagements", headers=agent_headers, json=make_signed_auth())
    assert r.status_code == 403


def test_operator_can_create(client, op_headers, make_signed_auth):
    assert client.post("/engagements", headers=op_headers, json=make_signed_auth()).status_code == 201


def test_auth_disabled_treats_caller_as_operator():
    cfg = ControlPlaneConfig(
        api_keys={}, signing_keys={"kid": "s"}, require_signature=True, auth_enabled=False
    )
    c = TestClient(create_app(cfg))
    # No Authorization header, yet an operator-only read succeeds.
    assert c.get("/engagements").status_code == 200
