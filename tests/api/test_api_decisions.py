def _decisions(eid: str) -> str:
    return f"/engagements/{eid}/decisions"


def test_allow_passive(client, agent_headers, registered):
    eid = registered["authorization_id"]
    r = client.post(
        _decisions(eid),
        headers=agent_headers,
        json={"target": "api.example.test", "action": "passive_discovery"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "allow"
    assert body["tier"] == "passive"
    assert body["authorization_id"] == eid


def test_out_of_scope_deny(client, agent_headers, registered):
    eid = registered["authorization_id"]
    r = client.post(
        _decisions(eid),
        headers=agent_headers,
        json={"target": "evil.example.com", "action": "passive_discovery"},
    )
    body = r.json()
    assert body["verdict"] == "deny"
    assert "SCOPE_ESCAPE" in body["incidents"]


def test_prohibited_deny(client, agent_headers, registered):
    eid = registered["authorization_id"]
    r = client.post(
        _decisions(eid),
        headers=agent_headers,
        json={"target": "api.example.test", "action": "denial_of_service"},
    )
    body = r.json()
    assert body["verdict"] == "deny"
    assert "PROHIBITED_ACTION_BLOCKED" in body["incidents"]


def test_requires_approval(client, agent_headers, registered):
    eid = registered["authorization_id"]
    r = client.post(
        _decisions(eid),
        headers=agent_headers,
        json={"target": "api.example.test", "action": "cross_tenant_proof"},
    )
    body = r.json()
    assert body["verdict"] == "require_approval"
    assert set(body["required_approvals"]) == {"cross_tenant_proof", "tier:SENSITIVE"}


def test_grant_then_allow(client, op_headers, agent_headers, registered):
    eid = registered["authorization_id"]
    g = client.post(
        f"/engagements/{eid}/approvals",
        headers=op_headers,
        json={"action": "cross_tenant_proof", "target": "api.example.test"},
    )
    assert g.status_code == 201
    d = client.post(
        _decisions(eid),
        headers=agent_headers,
        json={"target": "api.example.test", "action": "cross_tenant_proof"},
    )
    assert d.json()["verdict"] == "allow"


def test_commit_flow(client, agent_headers, registered):
    eid = registered["authorization_id"]
    d = client.post(
        _decisions(eid),
        headers=agent_headers,
        json={"target": "api.example.test", "action": "passive_discovery", "request_id": "req-1"},
    )
    assert d.json()["verdict"] == "allow"
    c = client.post(f"{_decisions(eid)}/req-1/commit", headers=agent_headers)
    assert c.status_code == 200
    assert c.json()["committed"] is True
    # second commit is rejected
    assert client.post(f"{_decisions(eid)}/req-1/commit", headers=agent_headers).status_code == 409


def test_commit_unknown_decision_404(client, agent_headers, registered):
    eid = registered["authorization_id"]
    assert client.post(f"{_decisions(eid)}/nope/commit", headers=agent_headers).status_code == 404


def test_commit_denied_decision_409(client, agent_headers, registered):
    eid = registered["authorization_id"]
    client.post(
        _decisions(eid),
        headers=agent_headers,
        json={"target": "evil.example.com", "action": "passive_discovery", "request_id": "req-d"},
    )
    assert client.post(f"{_decisions(eid)}/req-d/commit", headers=agent_headers).status_code == 409


def test_decision_on_closed_engagement_409(client, op_headers, agent_headers, registered):
    eid = registered["authorization_id"]
    client.delete(f"/engagements/{eid}", headers=op_headers)
    r = client.post(
        _decisions(eid),
        headers=agent_headers,
        json={"target": "api.example.test", "action": "passive_discovery"},
    )
    assert r.status_code == 409


def test_rate_budget_via_commits(client, op_headers, agent_headers, make_signed_auth):
    # A tight rps=1 engagement: one allow, commit, then denied.
    payload = make_signed_auth(rate_limits={"requests_per_second": 1, "max_concurrent_sessions": 3})
    eid = client.post("/engagements", headers=op_headers, json=payload).json()["id"]
    body = {"target": "api.example.test", "action": "passive_discovery", "request_id": "r1"}
    assert client.post(_decisions(eid), headers=agent_headers, json=body).json()["verdict"] == "allow"
    client.post(f"{_decisions(eid)}/r1/commit", headers=agent_headers)
    d2 = client.post(
        _decisions(eid),
        headers=agent_headers,
        json={"target": "api.example.test", "action": "passive_discovery"},
    )
    assert d2.json()["verdict"] == "deny"
    assert any(r["code"] == "rate_budget_exceeded" for r in d2.json()["reasons"])
