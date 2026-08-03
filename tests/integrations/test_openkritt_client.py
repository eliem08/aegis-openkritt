"""Live open·kritt connector — HTTP contract, driven by a mock transport.

No network is touched: an ``httpx.MockTransport`` returns open·kritt's real
serialized-vulnerability shape, and the client maps it to Aegis candidates.
"""

from __future__ import annotations

import httpx

from aegis.integrations import OpenKrittClient, ingest_openkritt_findings

# open·kritt's actual GET /api/scans/{id}/vulnerabilities response (serialized):
# the eight keys are flattened, canonical lives under dedupe, impact under bountyRank.
SERIALIZED = [
    {
        "id": "10", "scanId": "3", "rank": 1,
        "vulnerability_type": "Reentrancy", "file_path": "contracts/Vault.sol", "line": 42,
        "summary": "withdraw() calls out before settling balances",
        "explanation": "external call precedes balance write", "trigger_flow": "…",
        "malicious_input_example": "PAYLOAD_SENTINEL", "malicious_actor": "any caller",
        "exploitable": True,
        "jsonAnswer": {"vulnerability_type": "Reentrancy", "file_path": "contracts/Vault.sol",
                       "line": 42, "summary": "withdraw() calls out before settling balances",
                       "explanation": "external call precedes balance write",
                       "malicious_input_example": "PAYLOAD_SENTINEL"},
        "severity": None,
        "dedupe": {"isCanonical": True, "canonicalId": None, "clusterId": "c1"},
        "bountyRank": {"impactLevel": "critical", "rank": 1},
    },
]


def _client(handler) -> OpenKrittClient:
    transport = httpx.MockTransport(handler)
    return OpenKrittClient("http://okritt.local", client=httpx.Client(transport=transport))


def test_import_candidates_maps_serialized_shape():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["url"] = str(req.url)
        return httpx.Response(200, json=SERIALIZED)

    with _client(handler) as c:
        candidates = c.import_candidates("3")

    assert seen["url"] == "http://okritt.local/api/scans/3/vulnerabilities"
    assert len(candidates) == 1
    cand = candidates[0]
    assert cand.cwe == "CWE-841" and cand.worker == "integration:openkritt"
    assert cand.impact == "critical" and cand.business_impact == 0.95
    assert cand.code_location == "contracts/Vault.sol:42"
    # the exploit payload is never carried into the candidate
    assert "PAYLOAD_SENTINEL" not in (cand.observed + cand.expected + cand.preconditions)


def test_serialized_shape_is_ingestible_directly():
    # the raw serialized rows also work through the plain ingest function
    assert len(ingest_openkritt_findings(SERIALIZED)) == 1


def test_list_scans_and_create_scan():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "GET" and req.url.path == "/api/scans":
            return httpx.Response(200, json=[{"id": "3"}, {"id": "4"}])
        if req.method == "POST" and req.url.path == "/api/scans":
            return httpx.Response(201, json={"id": "5", "status": "queued"})
        return httpx.Response(404, json={})

    with _client(handler) as c:
        assert len(c.list_scans()) == 2
        assert c.create_scan({"workflowId": 1})["id"] == "5"


def test_api_key_becomes_a_bearer_header():
    captured = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured["auth"] = req.headers.get("Authorization")
        return httpx.Response(200, json=[])

    client = OpenKrittClient("http://okritt.local", api_key="secret-token",
                             client=httpx.Client(transport=httpx.MockTransport(handler)))
    with client as c:
        c.list_scans()
    assert captured["auth"] == "Bearer secret-token"
