"""OpenAI-compatible model client with optional production gateway routing."""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field

import httpx

from .config import DeepSeekConfig

_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)
_USAGE_KEYS = frozenset({
    "prompt_tokens", "completion_tokens", "total_tokens",
    "prompt_cache_hit_tokens", "prompt_cache_miss_tokens", "cost",
})
_IDENTIFIER_CLEAN = re.compile(r"[^A-Za-z0-9_.:-]+")


class DeepSeekError(RuntimeError):
    """Any failure talking to the configured model boundary or parsing its response."""


@dataclass(frozen=True)
class DeepSeekCompletion:
    content: str
    model: str
    usage: dict[str, int | float] = field(default_factory=dict)
    request_id: str = ""
    latency_ms: int = 0


def _identifier(value: str, default: str) -> str:
    clean = _IDENTIFIER_CLEAN.sub("-", str(value or "").strip())[:128].strip("-")
    return clean or default


class DeepSeekClient:
    """Stable client API used by the hunt, validator and council.

    ``provider=gateway`` changes only the transport: the same callers are sent to Aegis's
    authenticated model gateway, which owns provider credentials, budget reservation, cache and
    usage-ledger reconciliation. Direct DeepSeek/OpenRouter remain development fallbacks.
    """

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

    def _direct_payload(
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

    def _gateway_payload(
        self,
        messages: list[dict],
        *,
        json_mode: bool,
        temperature: float | None,
        max_tokens: int | None,
    ) -> dict:
        return {
            "contract_version": 1,
            "tenant_id": _identifier(os.environ.get("AEGIS_TENANT_ID", "default"), "default"),
            "engagement_id": _identifier(
                os.environ.get("AEGIS_ENGAGEMENT_ID", "jarvis"), "jarvis"
            ),
            "task_id": _identifier(os.environ.get("AEGIS_MODEL_TASK_ID", "live-hunt"), "live-hunt"),
            "budget_id": _identifier(os.environ.get("AEGIS_MODEL_BUDGET_ID", "daily"), "daily"),
            "messages": [
                {"role": str(m.get("role") or "user"), "content": str(m.get("content") or "")}
                for m in messages
            ],
            "model": "deepseek-v4-flash",
            "json_mode": bool(json_mode),
            "thinking": self._config.thinking,
            "reasoning_effort": self._config.reasoning_effort,
            "max_tokens": self._config.max_tokens if max_tokens is None else max_tokens,
            "temperature": self._config.temperature if temperature is None else temperature,
            "cache_allowed": True,
        }

    _RETRY_STATUS = frozenset({429, 500, 502, 503, 504})

    def _post_with_retry(self, path: str, payload: dict) -> httpx.Response:
        attempts = self._config.max_retries + 1
        last: Exception | None = None
        for attempt in range(attempts):
            try:
                resp = self._client.post(path, json=payload, headers=self._headers)
            except httpx.TransportError as exc:
                last = DeepSeekError(f"model request failed: {exc}")
            except httpx.HTTPError as exc:
                raise DeepSeekError(f"model request failed: {exc}") from exc
            else:
                if resp.status_code < 400:
                    return resp
                if resp.status_code not in self._RETRY_STATUS:
                    detail = ""
                    try:
                        detail = str(resp.json().get("detail") or "")[:120]
                    except Exception:
                        pass
                    raise DeepSeekError(
                        f"model HTTP {resp.status_code}" + (f": {detail}" if detail else "")
                    )
                last = DeepSeekError(f"model HTTP {resp.status_code}")
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
        started = time.monotonic()
        if self._config.provider == "gateway":
            payload = self._gateway_payload(
                messages, json_mode=json_mode, temperature=temperature, max_tokens=max_tokens
            )
            resp = self._post_with_retry("/v1/completions", payload)
            try:
                body = resp.json()
                content = body["content"]
                if not isinstance(content, str):
                    raise TypeError("content is not text")
                raw_usage = body.get("usage") if isinstance(body, dict) else None
                model = str(body.get("model") or "deepseek-v4-flash")
                request_id = str(body.get("request_id") or "")
                latency_ms = int(body.get("latency_ms") or 0)
            except (KeyError, ValueError, TypeError) as exc:
                raise DeepSeekError("unexpected model-gateway response shape") from exc
        else:
            payload = self._direct_payload(
                messages, json_mode=json_mode, temperature=temperature, max_tokens=max_tokens
            )
            resp = self._post_with_retry("/chat/completions", payload)
            try:
                body = resp.json()
                content = body["choices"][0]["message"]["content"]
                if not isinstance(content, str):
                    raise TypeError("content is not text")
            except (KeyError, IndexError, ValueError, TypeError) as exc:
                raise DeepSeekError("unexpected provider response shape") from exc
            raw_usage = body.get("usage") if isinstance(body, dict) else None
            model = str(body.get("model") or self._config.model)
            request_id = resp.headers.get("x-request-id", "")
            latency_ms = max(0, round((time.monotonic() - started) * 1000))

        usage = {
            key: value
            for key, value in (raw_usage or {}).items()
            if key in _USAGE_KEYS and isinstance(value, (int, float)) and not isinstance(value, bool)
        }
        try:
            from .cost import TRACKER
            TRACKER.record(usage)
        except Exception:
            pass
        return DeepSeekCompletion(
            content=content,
            model=model,
            usage=usage,
            request_id=request_id,
            latency_ms=latency_ms or max(0, round((time.monotonic() - started) * 1000)),
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
            raise DeepSeekError("model did not return valid JSON")

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "DeepSeekClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
