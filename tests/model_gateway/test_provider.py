import json

import httpx
import pytest

from aegis.model_gateway import GatewayMessage, ModelGatewayConfig, ModelGatewayRequest
from aegis.model_gateway.provider import CircuitBreaker, DeepSeekProvider, ProviderError


def _config(**changes):
    data = dict(
        provider_api_key="provider-secret",
        caller_token="x" * 48,
        max_attempts=3,
        circuit_failures=2,
        circuit_cooldown=10,
    )
    data.update(changes)
    return ModelGatewayConfig(**data)


def _request(**changes):
    data = dict(
        tenant_id="tenant-a",
        engagement_id="eng-1",
        task_id="task-1",
        budget_id="budget-1",
        messages=[GatewayMessage(role="user", content="return json")],
    )
    data.update(changes)
    return ModelGatewayRequest(**data)


def _response(content='{"ok":true}'):
    return {
        "model": "deepseek-v4-flash",
        "choices": [{"message": {"content": content, "reasoning_content": "not returned"}}],
        "usage": {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3},
    }


def test_provider_sends_v4_controls_and_returns_sanitized_result():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["auth"] = request.headers["authorization"]
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, headers={"x-request-id": "req-1"}, json=_response())

    client = httpx.Client(
        transport=httpx.MockTransport(handler), base_url="https://api.deepseek.com",
    )
    result = DeepSeekProvider(_config(), client=client).complete(_request())
    assert seen["url"] == "https://api.deepseek.com/chat/completions"
    assert seen["auth"] == "Bearer provider-secret"
    assert seen["body"]["thinking"] == {"type": "enabled"}
    assert "temperature" not in seen["body"]
    assert result.content == '{"ok":true}'
    assert result.request_id == "req-1"
    assert result.usage.total_tokens == 3
    assert not hasattr(result, "reasoning_content")


def test_retry_honors_retry_after_then_succeeds():
    calls = 0
    sleeps = []

    def handler(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"retry-after": "2"})
        return httpx.Response(200, json=_response())

    client = httpx.Client(
        transport=httpx.MockTransport(handler), base_url="https://api.deepseek.com",
    )
    result = DeepSeekProvider(_config(), client=client, sleep=sleeps.append).complete(_request())
    assert result.content == '{"ok":true}'
    assert sleeps == [2.0]


def test_invalid_json_is_rejected_without_provider_body_in_error():
    client = httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json=_response("secret prose"))),
        base_url="https://api.deepseek.com",
    )
    with pytest.raises(ProviderError, match="invalid_provider_response") as caught:
        DeepSeekProvider(_config(), client=client).complete(_request())
    assert "secret prose" not in str(caught.value)


def test_circuit_opens_and_allows_one_probe_after_cooldown():
    now = [0.0]
    breaker = CircuitBreaker(2, 10, clock=lambda: now[0])
    breaker.failure()
    breaker.failure()
    with pytest.raises(ProviderError, match="circuit_open"):
        breaker.before_call()
    now[0] = 11
    breaker.before_call()
    with pytest.raises(ProviderError, match="circuit_open"):
        breaker.before_call()
    breaker.success()
    breaker.before_call()
