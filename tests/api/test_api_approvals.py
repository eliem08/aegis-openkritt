def _approvals(eid: str) -> str:
    return f"/engagements/{eid}/approvals"


def _decisions(eid: str) -> str:
    return f"/engagements/{eid}/decisions"


def test_grant_auto_computes_tokens(client, op_headers, registered):
    eid = registered["authorization_id"]
    r = client.post(
        _approvals(eid),
        headers=op_headers,
        json={"action": "cross_tenant_proof", "target": "api.example.test"},
    )
    assert r.status_code == 201
    assert set(r.json()["tokens"]) == {"cross_tenant_proof", "tier:SENSITIVE"}


def test_grant_explicit_tokens(client, op_headers, registered):
    eid = registered["authorization_id"]
    r = client.post(
        _approvals(eid),
        headers=op_headers,
        json={
            "action": "cross_tenant_proof",
            "target": "api.example.test",
            "tokens": ["cross_tenant_proof", "tier:SENSITIVE"],
        },
    )
    assert r.status_code == 201


def test_grant_when_none_required_400(client, op_headers, registered):
    eid = registered["authorization_id"]
    r = client.post(
        _approvals(eid),
        headers=op_headers,
        json={"action": "passive_discovery", "target": "api.example.test"},
    )
    assert r.status_code == 400


def test_list_and_revoke(client, op_headers, registered):
    eid = registered["authorization_id"]
    gid = client.post(
        _approvals(eid),
        headers=op_headers,
        json={"action": "cross_tenant_proof", "target": "api.example.test"},
    ).json()["grant_id"]

    listed = client.get(_approvals(eid), headers=op_headers)
    assert listed.status_code == 200
    assert any(g["grant_id"] == gid for g in listed.json())

    assert client.delete(f"{_approvals(eid)}/{gid}", headers=op_headers).status_code == 204
    # revoking again is a 404
    assert client.delete(f"{_approvals(eid)}/{gid}", headers=op_headers).status_code == 404


def test_revoked_grant_no_longer_allows(client, op_headers, agent_headers, registered):
    eid = registered["authorization_id"]
    gid = client.post(
        _approvals(eid),
        headers=op_headers,
        json={"action": "cross_tenant_proof", "target": "api.example.test"},
    ).json()["grant_id"]
    # allowed while grant is active
    d1 = client.post(
        _decisions(eid),
        headers=agent_headers,
        json={"target": "api.example.test", "action": "cross_tenant_proof"},
    )
    assert d1.json()["verdict"] == "allow"
    client.delete(f"{_approvals(eid)}/{gid}", headers=op_headers)
    d2 = client.post(
        _decisions(eid),
        headers=agent_headers,
        json={"target": "api.example.test", "action": "cross_tenant_proof"},
    )
    assert d2.json()["verdict"] == "require_approval"


def test_single_use_grant_consumed(client, op_headers, agent_headers, registered):
    eid = registered["authorization_id"]
    client.post(
        _approvals(eid),
        headers=op_headers,
        json={"action": "cross_tenant_proof", "target": "api.example.test", "single_use": True},
    )
    first = client.post(
        _decisions(eid),
        headers=agent_headers,
        json={"target": "api.example.test", "action": "cross_tenant_proof"},
    )
    assert first.json()["verdict"] == "allow"
    second = client.post(
        _decisions(eid),
        headers=agent_headers,
        json={"target": "api.example.test", "action": "cross_tenant_proof"},
    )
    assert second.json()["verdict"] == "require_approval"


def test_agent_cannot_grant(client, agent_headers, registered):
    eid = registered["authorization_id"]
    r = client.post(
        _approvals(eid),
        headers=agent_headers,
        json={"action": "cross_tenant_proof", "target": "api.example.test"},
    )
    assert r.status_code == 403
