"""State-changing operator UI routes must not be an unauthenticated control plane."""


def test_mutating_ui_requires_bearer_token(client):
    response = client.post("/ui/autohunt", json={})
    assert response.status_code == 401
    assert response.json()["detail"] == "missing bearer token"


def test_mutating_ui_rejects_agent_role(client, agent_headers):
    response = client.post("/ui/autohunt", headers=agent_headers, json={})
    assert response.status_code == 403
    assert "operator role" in response.json()["detail"]


def test_mutating_ui_accepts_operator_then_reaches_route(client, op_headers):
    response = client.post("/ui/autohunt", headers=op_headers, json={})
    assert response.status_code == 200
    assert "error" in response.json()  # route ran; no ranking fixture was supplied
