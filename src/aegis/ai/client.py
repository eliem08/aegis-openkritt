"""Minimal OpenAI-compatible DeepSeek client with sanitized usage metadata."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field

import httpx

from .config import DeepSeekConfig

_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)
_USAGE_KEYS = frozenset({
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "prompt_cache_hit_tokens",
    "prompt_cache_miss_tokens",
})


class DeepSeekError(RuntimeError):
    """Any failure talking to DeepSeek or parsing its response."""


@dataclass(frozen=True)
class DeepSeekCompletion:
    """Final content plus non-sensitive provider accounting metadata."""

    content: str
    model: str
    usage: dict[str, int | float] = field(default_factory=dict)
    request_id: str = ""
    latency_ms: int = 0


class DeepSeekClient:
    def __init__(self, config: DeepSeekConfig, *, client: httpx.Client | None = None) -> None:
        self._config = config
        self._owns_client = client is None
        self._headers = {
            "Authorization": f"Bearer {config.api_key}",
            "Content-Type": "application/json",
        }
        self._client = client or httpx.Client(base_url=config.base_url, timeout=config.timeout)

    @classmethod
    def from_env(cls, env: dict | None = None, **kwargs) -> "DeepSeekClient":
        return cls(DeepSeekConfig.from_env(env), **kwargs)

    def _payload(
        self,
        messages: list[dict],
        *,
        json_mode: bool,
        temperature: float | None,
        max_tokens: int | None,
    ) -> dict:
        payload: dict = {
            "model": self._config.model,
            "messages": messages,
            "stream": False,
            "max_tokens": self._config.max_tokens if max_tokens is None else max_tokens,
        }
        # DeepSeek's native API takes a `thinking` field; OpenRouter's OpenAI-compat API
        # rejects it. Only send DeepSeek-specific params to the DeepSeek provider.
        if self._config.provider == "deepseek":
            payload["thinking"] = {"type": self._config.thinking}
        if self._config.provider == "deepseek" and self._config.thinking == "enabled":
            payload["reasoning_effort"] = self._config.reasoning_effort
        else:
            payload["temperature"] = (
                self._config.temperature if temperature is None else temperature
            )
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        return payload

    #: transient upstream statuses worth retrying (rate limit + gateway/5xx).
    _RETRY_STATUS = frozenset({429, 500, 502, 503, 504})

    def _post_with_retry(self, payload: dict) -> httpx.Response:
        """POST with bounded exponential backoff on transient failures.

        DNS/connect/timeout errors (httpx.TransportError — the ``getaddrinfo failed``
        class that invalidated whole hunt runs) and 429/5xx are retried; 4xx client
        errors fail fast. Backoff is ``retry_backoff * 2**attempt`` seconds."""
        attempts = self._config.max_retries + 1
        last: Exception | None = None
        for attempt in range(attempts):
            try:
                resp = self._client.post("/chat/completions", json=payload,
                                         headers=self._headers)
            except httpx.TransportError as exc:            # DNS/connect/read/network
                last = DeepSeekError(f"DeepSeek request failed: {exc}")
            except httpx.HTTPError as exc:                 # other httpx errors: don't retry
                raise DeepSeekError(f"DeepSeek request failed: {exc}") from exc
            else:
                if resp.status_code < 400:
                    return resp
                if resp.status_code not in self._RETRY_STATUS:
                    raise DeepSeekError(f"DeepSeek HTTP {resp.status_code}")  # 4xx: fail fast
                last = DeepSeekError(f"DeepSeek HTTP {resp.status_code}")     # transient: retry
            if attempt < attempts - 1 and self._config.retry_backoff > 0:
                time.sleep(self._config.retry_backoff * (2 ** attempt))
        assert last is not None
        raise last

    def complete_result(
        self,
        messages: list[dict],
        *,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> DeepSeekCompletion:
        payload = self._payload(
            messages,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        started = time.monotonic()
        resp = self._post_with_retry(payload)

        try:
            body = resp.json()
            content = body["choices"][0]["message"]["content"]
            if not isinstance(content, str):
                raise TypeError("content is not text")
        except (KeyError, IndexError, ValueError, TypeError) as exc:
            raise DeepSeekError("unexpected DeepSeek response shape") from exc

        raw_usage = body.get("usage") if isinstance(body, dict) else None
        usage = {
            key: value
            for key, value in (raw_usage or {}).items()
            if key in _USAGE_KEYS and isinstance(value, (int, float)) and not isinstance(value, bool)
        }
        # aggregate spend for the budget tracker (best-effort; never breaks a call)
        try:
            from .cost import TRACKER
            TRACKER.record(usage)
        except Exception:
            pass
        return DeepSeekCompletion(
            content=content,
            model=str(body.get("model") or self._config.model),
            usage=usage,
            request_id=resp.headers.get("x-request-id", ""),
            latency_ms=max(0, round((time.monotonic() - started) * 1000)),
        )

    def complete(
        self,
        messages: list[dict],
        *,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        return self.complete_result(
            messages,
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
        ).content

    def complete_json(self, messages: list[dict], **kwargs) -> dict:
        content = self.complete(messages, json_mode=True, **kwargs)
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            match = _JSON_OBJECT_RE.search(content or "")
            if match:
                try:
                    return json.loads(match.group(0))
                except json.JSONDecodeError:
                    pass
            raise DeepSeekError("DeepSeek did not return valid JSON")

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "DeepSeekClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
