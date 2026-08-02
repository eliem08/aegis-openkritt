def test_audit_records_decisions(client, op_headers, agent_headers, registered):
    eid = registered["authorization_id"]
    client.post(
        f"/engagements/{eid}/decisions",
        headers=agent_headers,
        json={"target": "api.example.test", "action": "passive_discovery"},
    )
    r = client.get(f"/engagements/{eid}/audit", headers=op_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["engagement_id"] == eid
    assert body["count"] >= 1
    assert body["records"][-1]["action"] == "passive_discovery"


def test_audit_forbidden_to_agent(client, agent_headers, registered):
    eid = registered["authorization_id"]
    assert client.get(f"/engagements/{eid}/audit", headers=agent_headers).status_code == 403


def test_audit_limit_validation(client, op_headers, registered):
    eid = registered["authorization_id"]
    assert client.get(f"/engagements/{eid}/audit?limit=0", headers=op_headers).status_code == 422
