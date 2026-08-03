import json

import httpx
import pytest

from aegis.ai.client import DeepSeekError
from aegis.ai.gateway_client import GatewayIdentity, ModelGatewayClient


IDENTITY = GatewayIdentity("tenant-a", "eng-1", "task-1", "cycle-1")


def test_gateway_client_adds_identity_and_parses_content():
    seen = {}

    def handler(request):
        seen["auth"] = request.headers["authorization"]
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={
            "contract_version": 1,
            "content": '{"actions":[]}',
            "model": "deepseek-v4-flash",
            "usage": {},
            "cache_hit": False,
            "latency_ms": 2,
            "request_id": "",
        })

    http = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://model")
    client = ModelGatewayClient("http://model", "x" * 48, IDENTITY, client=http)
    assert client.complete_json([{"role": "user", "content": "json"}]) == {"actions": []}
    assert seen["auth"] == f"Bearer {'x' * 48}"
    assert seen["body"]["tenant_id"] == "tenant-a"
    assert seen["body"]["budget_id"] == "cycle-1"


def test_gateway_failure_is_planner_compatible_error():
    http = httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(503, json={"detail": "down"})),
        base_url="http://model",
    )
    client = ModelGatewayClient("http://model", "x" * 48, IDENTITY, client=http)
    with pytest.raises(DeepSeekError, match="HTTP 503"):
        client.complete_json([{"role": "user", "content": "json"}])
