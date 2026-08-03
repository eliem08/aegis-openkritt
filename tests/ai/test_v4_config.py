import json

import httpx
import pytest

from aegis.ai import DeepSeekClient, DeepSeekConfig
from aegis.ai.config import DeepSeekConfigError


def _response(content="ok", **extra):
    return {
        "choices": [{"message": {"role": "assistant", "content": content}}],
        **extra,
    }


def test_from_env_parses_v4_controls():
    cfg = DeepSeekConfig.from_env(env={
        "DEEPSEEK_API_KEY": "abc",
        "DEEPSEEK_BASE_URL": "https://api.deepseek.com/",
        "DEEPSEEK_MODEL": "deepseek-v4-flash",
        "DEEPSEEK_CONNECT_TIMEOUT": "4.5",
        "DEEPSEEK_READ_TIMEOUT": "80",
        "DEEPSEEK_MAX_TOKENS": "4096",
        "DEEPSEEK_TEMPERATURE": "0.1",
        "DEEPSEEK_THINKING": "disabled",
        "DEEPSEEK_REASONING_EFFORT": "max",
    })
    assert cfg.base_url == "https://api.deepseek.com"
    assert cfg.connect_timeout == 4.5
    assert cfg.read_timeout == 80
    assert cfg.max_tokens == 4096
    assert cfg.temperature == 0.1
    assert cfg.thinking == "disabled"
    assert cfg.reasoning_effort == "max"


@pytest.mark.parametrize("env", [
    {"DEEPSEEK_API_KEY": "k", "DEEPSEEK_BASE_URL": "ftp://api.deepseek.com"},
    {"DEEPSEEK_API_KEY": "k", "DEEPSEEK_BASE_URL": "https://user:pass@api.deepseek.com"},
    {"DEEPSEEK_API_KEY": "k", "DEEPSEEK_CONNECT_TIMEOUT": "0"},
    {"DEEPSEEK_API_KEY": "k", "DEEPSEEK_READ_TIMEOUT": "nan"},
    {"DEEPSEEK_API_KEY": "k", "DEEPSEEK_MAX_TOKENS": "0"},
    {"DEEPSEEK_API_KEY": "k", "DEEPSEEK_TEMPERATURE": "3"},
    {"DEEPSEEK_API_KEY": "k", "DEEPSEEK_THINKING": "sometimes"},
    {"DEEPSEEK_API_KEY": "k", "DEEPSEEK_REASONING_EFFORT": "extreme"},
])
def test_invalid_config_fails_before_request(env):
    with pytest.raises(DeepSeekConfigError):
        DeepSeekConfig.from_env(env=env)


def test_thinking_request_omits_unsupported_temperature():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json=_response())

    http = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://api.deepseek.com")
    DeepSeekClient(DeepSeekConfig(api_key="k"), client=http).complete(
        [{"role": "user", "content": "return json"}], json_mode=True,
    )
    assert seen["body"]["thinking"] == {"type": "enabled"}
    assert seen["body"]["reasoning_effort"] == "high"
    assert "temperature" not in seen["body"]


def test_disabled_thinking_sends_temperature():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json=_response())

    http = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://api.deepseek.com")
    cfg = DeepSeekConfig(api_key="k", thinking="disabled", temperature=0.3)
    DeepSeekClient(cfg, client=http).complete([{"role": "user", "content": "x"}])
    assert seen["body"]["thinking"] == {"type": "disabled"}
    assert seen["body"]["temperature"] == 0.3
    assert "reasoning_effort" not in seen["body"]


def test_complete_result_exposes_usage_without_reasoning_content():
    response = _response(
        content="hello",
        model="DeepSeek-V4-Flash-0731",
        usage={"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10},
    )
    response["choices"][0]["message"]["reasoning_content"] = "private reasoning"
    http = httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(
            200, headers={"x-request-id": "req-123"}, json=response,
        )),
        base_url="https://api.deepseek.com",
    )
    result = DeepSeekClient(DeepSeekConfig(api_key="k"), client=http).complete_result(
        [{"role": "user", "content": "hi"}],
    )
    assert result.content == "hello"
    assert result.model == "DeepSeek-V4-Flash-0731"
    assert result.request_id == "req-123"
    assert result.usage["total_tokens"] == 10
    assert result.latency_ms >= 0
    assert not hasattr(result, "reasoning_content")
