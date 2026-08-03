"""Tenant-partitioned, content-addressed exact cache."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass

from .models import ModelGatewayRequest, ModelGatewayResponse


def _cache_key(request: ModelGatewayRequest) -> str:
    payload = request.model_dump(
        mode="json",
        exclude={"task_id", "budget_id", "cache_allowed"},
    )
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


@dataclass
class _Entry:
    expires_at: float
    response: ModelGatewayResponse


class ExactModelCache:
    def __init__(self, ttl_seconds: float = 300.0, *, clock=time.monotonic) -> None:
        self._ttl = max(0.0, ttl_seconds)
        self._clock = clock
        self._entries: dict[tuple[str, str], _Entry] = {}
        self._lock = threading.Lock()

    def key(self, request: ModelGatewayRequest) -> str:
        return _cache_key(request)

    def get(self, request: ModelGatewayRequest) -> ModelGatewayResponse | None:
        if not request.cache_allowed or self._ttl <= 0:
            return None
        cache_key = (request.tenant_id, _cache_key(request))
        now = self._clock()
        with self._lock:
            entry = self._entries.get(cache_key)
            if entry is None:
                return None
            if entry.expires_at <= now:
                self._entries.pop(cache_key, None)
                return None
            return entry.response.model_copy(update={"cache_hit": True, "latency_ms": 0})

    def put(self, request: ModelGatewayRequest, response: ModelGatewayResponse) -> None:
        if not request.cache_allowed or self._ttl <= 0:
            return
        clean = response.model_copy(update={"cache_hit": False})
        with self._lock:
            self._entries[(request.tenant_id, _cache_key(request))] = _Entry(
                expires_at=self._clock() + self._ttl,
                response=clean,
            )
