"""DeepSeek provider transport with bounded retry and circuit breaking."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass

import httpx

from .config import ModelGatewayConfig
from .models import ModelGatewayRequest, ModelGatewayResponse, ModelUsage

_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
_USAGE_FIELDS = frozenset(ModelUsage.model_fields)


class ProviderError(RuntimeError):
    def __init__(self, code: str, *, status_code: int | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


@dataclass
class _Circuit:
    failures: int = 0
    open_until: float = 0.0
    probe_active: bool = False


class CircuitBreaker:
    def __init__(self, threshold: int, cooldown: float, *, clock=time.monotonic) -> None:
        self._threshold = threshold
        self._cooldown = cooldown
        self._clock = clock
        self._state = _Circuit()
        self._lock = threading.Lock()

    def before_call(self) -> None:
        now = self._clock()
        with self._lock:
            if not self._state.open_until:
                return
            if now < self._state.open_until or self._state.probe_active:
                raise ProviderError("circuit_open")
            self._state.probe_active = True

    def success(self) -> None:
        with self._lock:
            self._state = _Circuit()

    def failure(self) -> None:
        now = self._clock()
        with self._lock:
            self._state.probe_active = False
            self._state.failures += 1
            if self._state.failures >= self._threshold:
                self._state.open_until = now + self._cooldown


class DeepSeekProvider:
    def __init__(
        self,
        config: ModelGatewayConfig,
        *,
        client: httpx.Client | None = None,
        sleep=time.sleep,
        clock=time.monotonic,
        breaker: CircuitBreaker | None = None,
    ) -> None:
        self._config = config
        self._sleep = sleep
        self._clock = clock
        self._headers = {
            "Authorization": f"Bearer {config.provider_api_key}",
            "Content-Type": "application/json",
        }
        timeout = httpx.Timeout(
            connect=config.connect_timeout,
            read=config.read_timeout,
            write=config.connect_timeout,
            pool=config.connect_timeout,
        )
        self._client = client or httpx.Client(
            base_url=config.provider_origin,
            timeout=timeout,
            follow_redirects=False,
        )
        self._owns_client = client is None
        self._breaker = breaker or CircuitBreaker(
            config.circuit_failures, config.circuit_cooldown, clock=clock,
        )

    def complete(self, request: ModelGatewayRequest) -> ModelGatewayResponse:
        self._breaker.before_call()
        payload = self._payload(request)
        started = self._clock()
        last_error = ProviderError("provider_unavailable")

        for attempt in range(1, self._config.max_attempts + 1):
            try:
                response = self._client.post(
                    "/chat/completions", json=payload, headers=self._headers,
                )
            except httpx.TimeoutException:
                last_error = ProviderError("provider_timeout")
            except httpx.HTTPError:
                last_error = ProviderError("provider_unavailable")
            else:
                if response.status_code == 200:
                    try:
                        result = self._parse(response, request, started)
                    except ProviderError as exc:
                        self._breaker.failure()
                        raise exc
                    self._breaker.success()
                    return result
                last_error = ProviderError(
                    "rate_limited" if response.status_code == 429 else "provider_http_error",
                    status_code=response.status_code,
                )
                if response.status_code not in _RETRYABLE_STATUS:
                    self._breaker.failure()
                    raise last_error

            if attempt < self._config.max_attempts:
                self._sleep(self._retry_delay(attempt, response if "response" in locals() else None))

        self._breaker.failure()
        raise last_error

    def _payload(self, request: ModelGatewayRequest) -> dict:
        payload = {
            "model": request.model,
            "messages": [message.model_dump() for message in request.messages],
            "stream": False,
            "max_tokens": request.max_tokens,
            "thinking": {"type": request.thinking},
        }
        if request.thinking == "enabled":
            payload["reasoning_effort"] = request.reasoning_effort
        else:
            payload["temperature"] = request.temperature
        if request.json_mode:
            payload["response_format"] = {"type": "json_object"}
        return payload

    def _parse(
        self,
        response: httpx.Response,
        request: ModelGatewayRequest,
        started: float,
    ) -> ModelGatewayResponse:
        try:
            body = response.json()
            content = body["choices"][0]["message"]["content"]
            if not isinstance(content, str) or not content:
                raise TypeError("empty content")
            if request.json_mode:
                json.loads(content)
            raw_usage = body.get("usage") or {}
            usage = ModelUsage(**{
                key: value for key, value in raw_usage.items() if key in _USAGE_FIELDS
            })
        except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ProviderError("invalid_provider_response") from exc
        return ModelGatewayResponse(
            content=content,
            model=str(body.get("model") or request.model),
            usage=usage,
            latency_ms=max(0, round((self._clock() - started) * 1000)),
            request_id=response.headers.get("x-request-id", ""),
        )

    @staticmethod
    def _retry_delay(attempt: int, response: httpx.Response | None) -> float:
        if response is not None:
            raw = response.headers.get("retry-after", "").strip()
            try:
                return min(30.0, max(0.0, float(raw)))
            except ValueError:
                pass
        return min(8.0, 0.25 * (2 ** (attempt - 1)))

    def close(self) -> None:
        if self._owns_client:
            self._client.close()
