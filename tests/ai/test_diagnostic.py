import json

from aegis.ai.__main__ import doctor
from aegis.ai.client import DeepSeekCompletion, DeepSeekError


class _Client:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.closed = False

    def complete_result(self, messages, **kwargs):
        assert "json" in " ".join(m["content"] for m in messages).lower()
        if self.error:
            raise self.error
        return self.result

    def close(self):
        self.closed = True


def test_doctor_is_offline_by_default(capsys):
    called = False

    def factory(config):
        nonlocal called
        called = True

    rc = doctor([], env={"DEEPSEEK_API_KEY": "secret"}, client_factory=factory)
    output = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert output["status"] == "configured"
    assert output["live"] is False
    assert output["model"] == "deepseek-v4-flash"
    assert called is False
    assert "secret" not in json.dumps(output)


def test_live_doctor_prints_usage_not_content_or_secret(capsys):
    client = _Client(DeepSeekCompletion(
        content='{"aegis_deepseek_live":true}',
        model="DeepSeek-V4-Flash-0731",
        usage={"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12},
        request_id="req-1",
        latency_ms=42,
    ))
    rc = doctor(
        ["--live"],
        env={"DEEPSEEK_API_KEY": "secret"},
        client_factory=lambda config: client,
    )
    raw = capsys.readouterr().out
    output = json.loads(raw)
    assert rc == 0
    assert output == {
        "live": True,
        "model": "DeepSeek-V4-Flash-0731",
        "status": "ok",
        "latency_ms": 42,
        "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12},
    }
    assert "secret" not in raw
    assert "do-not-print" not in raw
    assert "req-1" not in raw
    assert client.closed is True


def test_live_doctor_requires_key(capsys):
    rc = doctor(["--live"], env={})
    output = json.loads(capsys.readouterr().out)
    assert rc == 2
    assert output == {"live": True, "status": "not_configured"}


def test_live_doctor_sanitizes_provider_failure(capsys):
    client = _Client(error=DeepSeekError("provider body contained secret"))
    rc = doctor(
        ["--live"],
        env={"DEEPSEEK_API_KEY": "secret"},
        client_factory=lambda config: client,
    )
    raw = capsys.readouterr().out
    output = json.loads(raw)
    assert rc == 1
    assert output == {"live": True, "status": "provider_error"}
    assert "secret" not in raw
    assert "provider body" not in raw
    assert client.closed is True
