"""Redis-backed production coordination.

PostgreSQL remains the durable ledger. Redis holds only expiring rate windows,
semaphores, cancellation broadcasts, and deduplication keys. Lua keeps the two
operations that race across workers atomic.
"""

from __future__ import annotations

import time
from typing import Any

from .coordinator import CoordUnavailable, Coordinator

RATE_SCRIPT = """
local value = redis.call('INCR', KEYS[1])
if value == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return value
"""

ACQUIRE_SCRIPT = """
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[1])
if redis.call('ZSCORE', KEYS[1], ARGV[2]) then
  redis.call('ZADD', KEYS[1], ARGV[3], ARGV[2])
  redis.call('EXPIRE', KEYS[1], ARGV[4])
  return 1
end
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[5]) then return 0 end
redis.call('ZADD', KEYS[1], ARGV[3], ARGV[2])
redis.call('EXPIRE', KEYS[1], ARGV[4])
return 1
"""


class RedisBackend:
    """Protocol-compatible Redis storage with isolated key names.

    The client is injectable so tests do not need a Redis daemon. When omitted,
    redis-py is imported lazily from the production dependency set.
    """

    def __init__(
        self,
        url: str | None = None,
        *,
        client: Any | None = None,
        namespace: str = "aegis",
        tenant_id: str | None = None,
        socket_timeout: float = 2.0,
    ) -> None:
        if client is None:
            if not url:
                raise ValueError("a Redis URL or client is required")
            try:
                import redis
            except ImportError as exc:  # pragma: no cover - optional dependency
                raise RuntimeError("Redis support requires the production dependencies") from exc
            client = redis.Redis.from_url(
                url,
                decode_responses=True,
                socket_connect_timeout=socket_timeout,
                socket_timeout=socket_timeout,
                health_check_interval=30,
            )
        prefix = namespace.strip(" :")
        if not prefix:
            raise ValueError("coordination namespace must not be empty")
        self._client = client
        self._prefix = f"{prefix}:{tenant_id}:" if tenant_id else f"{prefix}:"

    def _key(self, key: str) -> str:
        if not key or any(character in key for character in "\r\n\x00"):
            raise ValueError("invalid coordination key")
        return self._prefix + key

    @staticmethod
    def _unavailable(exc: Exception) -> CoordUnavailable:
        return CoordUnavailable("Redis coordination backend is unavailable")

    def _call(self, operation, *args, **kwargs):
        try:
            return operation(*args, **kwargs)
        except Exception as exc:
            raise self._unavailable(exc) from exc

    @property
    def connected(self) -> bool:
        try:
            return bool(self._client.ping())
        except Exception:
            return False

    def close(self) -> None:
        close = getattr(self._client, "close", None)
        if close is not None:
            self._call(close)

    def incr_window(self, key: str, window_seconds: int) -> int:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        result = self._call(
            self._client.eval, RATE_SCRIPT, 1, self._key(key), window_seconds,
        )
        return int(result)

    def atomic_acquire(self, key: str, member: str, limit: int, ttl_seconds: int) -> bool:
        if limit <= 0 or ttl_seconds <= 0:
            return False
        now_ms = int(time.time() * 1000)
        result = self._call(
            self._client.eval,
            ACQUIRE_SCRIPT,
            1,
            self._key(key),
            now_ms,
            member,
            now_ms + ttl_seconds * 1000,
            ttl_seconds,
            limit,
        )
        return bool(int(result))

    def sadd(self, key: str, member: str, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        redis_key = self._key(key)
        expires_ms = int(time.time() * 1000) + ttl_seconds * 1000
        pipe = self._client.pipeline(transaction=True)
        pipe.zadd(redis_key, {member: expires_ms})
        pipe.expire(redis_key, ttl_seconds)
        self._call(pipe.execute)

    def srem(self, key: str, member: str) -> None:
        self._call(self._client.zrem, self._key(key), member)

    def members(self, key: str) -> set[str]:
        redis_key = self._key(key)
        pipe = self._client.pipeline(transaction=True)
        pipe.zremrangebyscore(redis_key, "-inf", int(time.time() * 1000))
        pipe.zrange(redis_key, 0, -1)
        result = self._call(pipe.execute)
        return {str(member) for member in result[-1]}

    def setnx(self, key: str, ttl_seconds: int) -> bool:
        if ttl_seconds <= 0:
            return False
        result = self._call(
            self._client.set, self._key(key), "1", nx=True, ex=ttl_seconds,
        )
        return bool(result)


class RedisCoordinator(Coordinator):
    """Coordinator that uses Redis' atomic semaphore operation."""

    def __init__(self, backend: RedisBackend, *, pause_passive_on_loss: bool = True) -> None:
        super().__init__(backend, pause_passive_on_loss=pause_passive_on_loss)
        self.redis_backend = backend

    def acquire(self, key: str, limit: int, holder: str, ttl_seconds: int = 300) -> bool:
        try:
            return self.redis_backend.atomic_acquire(key, holder, limit, ttl_seconds)
        except CoordUnavailable:
            return False
