"""Minimal DeepSeek chat client (OpenAI-compatible, httpx-based).

Kept dependency-light (httpx only, already required) rather than pulling the
openai SDK. Any ``httpx.Client`` can be injected — including a MockTransport
client for tests — so no live calls are needed to exercise callers.
"""

from __future__ import annotations

import json
import re

import httpx

from .config import DeepSeekConfig

_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


class DeepSeekError(RuntimeError):
    """Any failure talking to DeepSeek or parsing its response."""


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

    def complete(
        self,
        messages: list[dict],
        *,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        payload: dict = {
            "model": self._config.model,
            "messages": messages,
            "stream": False,
            "temperature": self._config.temperature if temperature is None else temperature,
            "max_tokens": self._config.max_tokens if max_tokens is None else max_tokens,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        try:
            resp = self._client.post("/chat/completions", json=payload, headers=self._headers)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise DeepSeekError(f"DeepSeek HTTP {exc.response.status_code}") from exc
        except httpx.HTTPError as exc:
            raise DeepSeekError(f"DeepSeek request failed: {exc}") from exc

        try:
            return resp.json()["choices"][0]["message"]["content"]
        except (KeyError, IndexError, ValueError, TypeError) as exc:
            raise DeepSeekError("unexpected DeepSeek response shape") from exc

    def complete_json(self, messages: list[dict], **kwargs) -> dict:
        content = self.complete(messages, json_mode=True, **kwargs)
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            # Some models wrap JSON in prose; salvage the first object.
            m = _JSON_OBJECT_RE.search(content or "")
            if m:
                try:
                    return json.loads(m.group(0))
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
