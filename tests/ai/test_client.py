import json as jsonlib

import httpx
import pytest

from aegis.ai import DeepSeekClient, DeepSeekConfig, DeepSeekError
from aegis.ai.config import DeepSeekAuthError


def _client(handler, **cfg) -> DeepSeekClient:
    http = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://api.deepseek.com")
    # retry_backoff=0 so tests never sleep; override via cfg where needed
    return DeepSeekClient(DeepSeekConfig(api_key="k", retry_backoff=0, **cfg), client=http)


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


def test_retries_transient_transport_error_then_succeeds():
    calls = {"n": 0}
    def handler(r):
        calls["n"] += 1
        if calls["n"] < 3:
            raise httpx.ConnectError("getaddrinfo failed")   # the exact hunt-killer
        return httpx.Response(200, json=_resp("ok"))
    c = _client(handler, max_retries=3)
    assert c.complete([{"role": "user", "content": "hi"}]) == "ok"
    assert calls["n"] == 3                                     # 2 failures + 1 success


def test_retries_429_then_succeeds():
    calls = {"n": 0}
    def handler(r):
        calls["n"] += 1
        return httpx.Response(429, json={}) if calls["n"] == 1 else httpx.Response(200, json=_resp("ok"))
    c = _client(handler, max_retries=3)
    assert c.complete([{"role": "user", "content": "hi"}]) == "ok"
    assert calls["n"] == 2


def test_4xx_fails_fast_without_retry():
    calls = {"n": 0}
    def handler(r):
        calls["n"] += 1
        return httpx.Response(400, json={"error": "bad request"})
    c = _client(handler, max_retries=3)
    with pytest.raises(DeepSeekError):
        c.complete([{"role": "user", "content": "hi"}])
    assert calls["n"] == 1                                     # no retries on client error


def test_transient_error_exhausts_retries_and_raises():
    calls = {"n": 0}
    def handler(r):
        calls["n"] += 1
        raise httpx.ConnectError("getaddrinfo failed")
    c = _client(handler, max_retries=2)
    with pytest.raises(DeepSeekError, match="request failed"):
        c.complete([{"role": "user", "content": "hi"}])
    assert calls["n"] == 3                                     # 1 initial + 2 retries
