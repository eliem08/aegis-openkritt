def test_kill_switch_flow(client, op_headers, agent_headers, registered):
    eid = registered["authorization_id"]
    decisions = f"/engagements/{eid}/decisions"
    kill = f"/engagements/{eid}/kill"

    assert client.get(kill, headers=agent_headers).json()["active"] is False

    fired = client.post(kill, headers=op_headers, json={"reason": "operator stop"})
    assert fired.status_code == 200
    assert fired.json()["active"] is True

    denied = client.post(
        decisions,
        headers=agent_headers,
        json={"target": "api.example.test", "action": "passive_discovery"},
    )
    assert denied.json()["verdict"] == "deny"
    assert "KILL_SWITCH" in denied.json()["incidents"]

    reset = client.post(f"{kill}/reset", headers=op_headers)
    assert reset.json()["active"] is False

    allowed = client.post(
        decisions,
        headers=agent_headers,
        json={"target": "api.example.test", "action": "passive_discovery"},
    )
    assert allowed.json()["verdict"] == "allow"


def test_kill_requires_reason(client, op_headers, registered):
    eid = registered["authorization_id"]
    r = client.post(f"/engagements/{eid}/kill", headers=op_headers, json={"reason": ""})
    assert r.status_code == 422


def test_agent_cannot_fire_kill(client, agent_headers, registered):
    eid = registered["authorization_id"]
    r = client.post(f"/engagements/{eid}/kill", headers=agent_headers, json={"reason": "x"})
    assert r.status_code == 403
