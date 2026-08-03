import json as jsonlib

import httpx
import pytest

from aegis.ai import DeepSeekClient, DeepSeekConfig, DeepSeekError
from aegis.ai.config import DeepSeekAuthError


def _client(handler) -> DeepSeekClient:
    http = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://api.deepseek.com")
    return DeepSeekClient(DeepSeekConfig(api_key="k"), client=http)


def _resp(content: str) -> dict:
    return {"choices": [{"message": {"role": "assistant", "content": content}}]}


def test_complete_returns_content():
    c = _client(lambda r: httpx.Response(200, json=_resp("hello")))
    assert c.complete([{"role": "user", "content": "hi"}]) == "hello"


def test_complete_json_parses():
    c = _client(lambda r: httpx.Response(200, json=_resp('{"a": 1}')))
    assert c.complete_json([{"role": "user", "content": "hi"}]) == {"a": 1}


def test_complete_json_salvages_wrapped_object():
    c = _client(lambda r: httpx.Response(200, json=_resp('sure: {"a": 1} done')))
    assert c.complete_json([{"role": "user", "content": "hi"}]) == {"a": 1}


def test_http_error_is_wrapped():
    c = _client(lambda r: httpx.Response(500, json={"error": "x"}))
    with pytest.raises(DeepSeekError):
        c.complete([{"role": "user", "content": "hi"}])


def test_unexpected_shape_raises():
    c = _client(lambda r: httpx.Response(200, json={"nope": 1}))
    with pytest.raises(DeepSeekError):
        c.complete([{"role": "user", "content": "hi"}])


def test_invalid_json_raises():
    c = _client(lambda r: httpx.Response(200, json=_resp("definitely not json")))
    with pytest.raises(DeepSeekError):
        c.complete_json([{"role": "user", "content": "hi"}])


def test_sends_auth_model_and_json_mode():
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = jsonlib.loads(request.content)
        return httpx.Response(200, json=_resp("ok"))

    _client(handler).complete([{"role": "user", "content": "x"}], json_mode=True)
    assert seen["auth"] == "Bearer k"
    assert seen["body"]["model"] == "deepseek-v4-flash"
    assert seen["body"]["stream"] is False
    assert seen["body"]["response_format"] == {"type": "json_object"}


def test_from_env_requires_key():
    with pytest.raises(DeepSeekAuthError):
        DeepSeekConfig.from_env(env={})
    assert DeepSeekConfig.maybe_from_env(env={}) is None
    cfg = DeepSeekConfig.from_env(env={"DEEPSEEK_API_KEY": "abc"})
    assert cfg.api_key == "abc" and cfg.model == "deepseek-v4-flash"
