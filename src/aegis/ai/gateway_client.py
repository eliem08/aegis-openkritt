"""Planner-compatible client for the internal production model gateway."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from aegis.model_gateway.models import ModelGatewayResponse

from .client import DeepSeekError


@dataclass(frozen=True)
class GatewayIdentity:
    tenant_id: str
    engagement_id: str
    task_id: str
    budget_id: str


class ModelGatewayClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        identity: GatewayIdentity,
        *,
        client: httpx.Client | None = None,
        timeout: float = 130.0,
    ) -> None:
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("model gateway URL must be HTTP(S)")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("model gateway URL cannot contain credentials")
        if len(token) < 32:
            raise ValueError("model gateway token is too short")
        self._identity = identity
        self._headers = {"Authorization": f"Bearer {token}"}
        self._owns_client = client is None
        self._client = client or httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout)

    @classmethod
    def from_files(
        cls,
        base_url: str,
        token_file: str | Path,
        identity: GatewayIdentity,
        **kwargs,
    ) -> "ModelGatewayClient":
        try:
            token = Path(token_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ValueError("cannot read model gateway token file") from exc
        return cls(base_url, token, identity, **kwargs)

    def complete_json(self, messages: list[dict], **kwargs) -> dict:
        payload = {
            "tenant_id": self._identity.tenant_id,
            "engagement_id": self._identity.engagement_id,
            "task_id": self._identity.task_id,
            "budget_id": self._identity.budget_id,
            "messages": messages,
            "json_mode": True,
            "max_tokens": kwargs.get("max_tokens", 4096),
            "thinking": kwargs.get("thinking", "enabled"),
            "reasoning_effort": kwargs.get("reasoning_effort", "high"),
            "cache_allowed": kwargs.get("cache_allowed", True),
        }
        try:
            response = self._client.post(
                "/v1/completions", headers=self._headers, json=payload,
            )
            response.raise_for_status()
            result = ModelGatewayResponse.model_validate(response.json())
            parsed = json.loads(result.content)
            if not isinstance(parsed, dict):
                raise TypeError("gateway JSON response is not an object")
            return parsed
        except httpx.HTTPStatusError as exc:
            raise DeepSeekError(f"model gateway HTTP {exc.response.status_code}") from exc
        except httpx.HTTPError as exc:
            raise DeepSeekError("model gateway unavailable") from exc
        except (ValueError, TypeError) as exc:
            raise DeepSeekError("invalid model gateway response") from exc

    def close(self) -> None:
        if self._owns_client:
            self._client.close()
