def test_create_and_get(client, op_headers, agent_headers, make_signed_auth):
    payload = make_signed_auth()
    r = client.post("/engagements", headers=op_headers, json=payload)
    assert r.status_code == 201, r.text
    eid = r.json()["id"]
    assert eid == payload["authorization_id"]

    g = client.get(f"/engagements/{eid}", headers=agent_headers)
    assert g.status_code == 200
    assert g.json()["status"] == "active"
    assert "api.example.test" in g.json()["targets"]


def test_duplicate_engagement_409(client, op_headers, make_signed_auth):
    payload = make_signed_auth()
    assert client.post("/engagements", headers=op_headers, json=payload).status_code == 201
    assert client.post("/engagements", headers=op_headers, json=payload).status_code == 409


def test_invalid_signature_rejected(client, op_headers, make_signed_auth):
    payload = make_signed_auth()
    payload["signature"] = "00" * 32
    r = client.post("/engagements", headers=op_headers, json=payload)
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "authorization_rejected"


def test_missing_signature_rejected(client, op_headers, make_signed_auth):
    payload = make_signed_auth()
    payload["signature"] = None
    payload["signing_key_id"] = None
    assert client.post("/engagements", headers=op_headers, json=payload).status_code == 422


def test_missing_ownership_proof_rejected(client, op_headers, make_signed_auth):
    payload = make_signed_auth(ownership_proof=[])
    assert client.post("/engagements", headers=op_headers, json=payload).status_code == 422


def test_malformed_body_422(client, op_headers):
    assert client.post("/engagements", headers=op_headers, json={"nope": 1}).status_code == 422


def test_list_engagements(client, op_headers, agent_headers, make_signed_auth):
    client.post("/engagements", headers=op_headers, json=make_signed_auth())
    r = client.get("/engagements", headers=agent_headers)
    assert r.status_code == 200
    assert len(r.json()) >= 1


def test_close_engagement(client, op_headers, make_signed_auth):
    eid = client.post("/engagements", headers=op_headers, json=make_signed_auth()).json()["id"]
    d = client.delete(f"/engagements/{eid}", headers=op_headers)
    assert d.status_code == 200
    assert d.json()["status"] == "closed"


def test_get_missing_engagement_404(client, agent_headers):
    assert client.get("/engagements/does-not-exist", headers=agent_headers).status_code == 404
