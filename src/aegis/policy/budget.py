"""Rate, concurrency and spend budgets (Master Prompt §4 ``rate_limits``, §8).

These are *stateful* — they track consumption over the life of an engagement.
The engine reads them (non-mutating ``check``) when forming a decision and only
records consumption (``consume`` / ``record``) once an action is committed, so a
denied-or-queued action never burns budget.

The rate limiter is a token bucket, which handles fractional rates
(``requests_per_second < 1``) cleanly, unlike a fixed 1-second window.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass
class TokenBucket:
    """A monotonic token bucket. ``rate`` tokens accrue per second up to
    ``capacity``; each request costs one token."""

    rate: float
    capacity: float
    _tokens: float = field(default=0.0)
    _last: float | None = field(default=None)

    def __post_init__(self) -> None:
        if self.rate <= 0:
            raise ValueError("rate must be > 0")
        if self.capacity <= 0:
            raise ValueError("capacity must be > 0")
        if self._tokens == 0.0:
            self._tokens = self.capacity  # start full

    def _refill(self, now: float) -> None:
        if self._last is None:
            self._last = now
            return
        if now <= self._last:
            return
        elapsed = now - self._last
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last = now

    def available(self, now: float) -> float:
        self._refill(now)
        return self._tokens

    def check(self, now: float, cost: float = 1.0) -> bool:
        return self.available(now) >= cost

    def consume(self, now: float, cost: float = 1.0) -> bool:
        self._refill(now)
        if self._tokens >= cost:
            self._tokens -= cost
            return True
        return False


class RateBudget:
    """Requests-per-second plus a concurrent-session cap."""

    def __init__(self, requests_per_second: float, max_concurrent_sessions: int) -> None:
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be > 0")
        if max_concurrent_sessions < 1:
            raise ValueError("max_concurrent_sessions must be >= 1")
        capacity = max(requests_per_second, 1.0)
        self._bucket = TokenBucket(rate=requests_per_second, capacity=capacity)
        self._max_sessions = max_concurrent_sessions
        self._active_sessions = 0
        self._lock = threading.Lock()

    def check_rate(self, now: float) -> bool:
        with self._lock:
            return self._bucket.check(now)

    def consume_rate(self, now: float) -> bool:
        with self._lock:
            return self._bucket.consume(now)

    def has_session_capacity(self) -> bool:
        with self._lock:
            return self._active_sessions < self._max_sessions

    def acquire_session(self) -> bool:
        with self._lock:
            if self._active_sessions >= self._max_sessions:
                return False
            self._active_sessions += 1
            return True

    def release_session(self) -> None:
        with self._lock:
            if self._active_sessions > 0:
                self._active_sessions -= 1

    @property
    def active_sessions(self) -> int:
        return self._active_sessions


class SpendBudget:
    """A simple monetary / unit spend cap. ``limit=None`` means unlimited."""

    def __init__(self, limit: float | None = None, spent: float = 0.0) -> None:
        if limit is not None and limit < 0:
            raise ValueError("limit must be >= 0")
        self._limit = limit
        self._spent = spent
        self._lock = threading.Lock()

    def check(self, amount: float) -> bool:
        if amount < 0:
            raise ValueError("amount must be >= 0")
        with self._lock:
            return self._limit is None or (self._spent + amount) <= self._limit

    def record(self, amount: float) -> None:
        if amount < 0:
            raise ValueError("amount must be >= 0")
        with self._lock:
            self._spent += amount

    @property
    def spent(self) -> float:
        return self._spent

    @property
    def remaining(self) -> float:
        return float("inf") if self._limit is None else max(0.0, self._limit - self._spent)
