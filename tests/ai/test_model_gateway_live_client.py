from __future__ import annotations

import json

import httpx

from aegis.ai.client import DeepSeekClient
from aegis.ai.config import DeepSeekConfig


def test_gateway_config_does_not_require_provider_key():
    cfg = DeepSeekConfig.from_env({
        "AEGIS_MODEL_GATEWAY_URL": "http://gateway.internal:8091",
        "AEGIS_MODEL_GATEWAY_TOKEN": "caller-secret",
    })
    assert cfg.provider == "gateway"
    assert cfg.api_key == "caller-secret"
    assert cfg.model == "deepseek-v4-flash"


def test_existing_deepseek_client_routes_through_gateway(monkeypatch):
    monkeypatch.setenv("AEGIS_TENANT_ID", "tenant-a")
    monkeypatch.setenv("AEGIS_ENGAGEMENT_ID", "engagement-1")
    monkeypatch.setenv("AEGIS_MODEL_TASK_ID", "skeptic:42")
    monkeypatch.setenv("AEGIS_MODEL_BUDGET_ID", "daily-2026-08-08")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={
            "contract_version": 1,
            "content": '{"verdict":"pass"}',
            "model": "deepseek-v4-flash",
            "usage": {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14,
                      "prompt_cache_hit_tokens": 0, "prompt_cache_miss_tokens": 10},
            "cache_hit": False,
            "latency_ms": 12,
            "request_id": "gw-1",
        })

    transport = httpx.MockTransport(handler)
    http = httpx.Client(transport=transport, base_url="http://gateway.internal:8091")
    cfg = DeepSeekConfig.from_env({
        "AEGIS_MODEL_GATEWAY_URL": "http://gateway.internal:8091",
        "AEGIS_MODEL_GATEWAY_TOKEN": "caller-secret",
        "DEEPSEEK_THINKING": "disabled",
    })
    with DeepSeekClient(cfg, client=http) as client:
        result = client.complete_json([{"role": "user", "content": "review"}])

    assert result == {"verdict": "pass"}
    assert seen["path"] == "/v1/completions"
    assert seen["auth"] == "Bearer caller-secret"
    assert seen["body"]["tenant_id"] == "tenant-a"
    assert seen["body"]["engagement_id"] == "engagement-1"
    assert seen["body"]["task_id"] == "skeptic:42"
    assert seen["body"]["budget_id"] == "daily-2026-08-08"
    assert seen["body"]["json_mode"] is True
