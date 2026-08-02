"""Distributed coordination (Phase 5 §Distributed coordination).

Ephemeral cross-worker coordination — rate buckets, concurrency semaphores,
cancellation broadcasts, and short-lived deduplication — over a Redis-shaped
backend. PostgreSQL stays the source of truth for terminal task/reservation
state; this layer is best-effort *coordination*, never the ledger.

The safety rule is **fail closed**: if the backend is unavailable, new *active*
work is denied and a cancellation cannot be disproven (so work stops). Passive-
provider work may be configured to **pause** instead. Reconciliation rebuilds the
semaphores from durable leases without ever touching reservations.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum

PASSIVE_TIERS = frozenset({"passive_discovery"})


class CoordUnavailable(RuntimeError):
    """The coordination backend cannot be reached."""


class Admission(str, Enum):
    ADMIT = "admit"
    DENY = "deny"       # fail closed — active work is refused
    PAUSE = "pause"     # passive work may wait for the backend to return


def _now() -> datetime:
    return datetime.now(timezone.utc)


class InMemoryBackend:
    """A fake Redis for tests; ``connected=False`` simulates an outage."""

    def __init__(self, clock=None) -> None:
        self._clock = clock or _now
        self.connected = True
        self._counters: dict[str, tuple[datetime, int]] = {}     # key -> (reset_at, count)
        self._sets: dict[str, dict[str, datetime]] = {}          # key -> {member: expires_at}
        self._keys: dict[str, datetime] = {}                     # key -> expires_at (setnx)

    def _check(self) -> None:
        if not self.connected:
            raise CoordUnavailable("coordination backend is down")

    def incr_window(self, key: str, window_seconds: int) -> int:
        self._check()
        now = self._clock()
        reset_at, count = self._counters.get(key, (now + timedelta(seconds=window_seconds), 0))
        if now >= reset_at:
            reset_at, count = now + timedelta(seconds=window_seconds), 0
        count += 1
        self._counters[key] = (reset_at, count)
        return count

    def sadd(self, key: str, member: str, ttl_seconds: int) -> None:
        self._check()
        self._sets.setdefault(key, {})[member] = self._clock() + timedelta(seconds=ttl_seconds)

    def srem(self, key: str, member: str) -> None:
        self._check()
        self._sets.get(key, {}).pop(member, None)

    def members(self, key: str) -> set[str]:
        self._check()
        now = self._clock()
        live = {m: exp for m, exp in self._sets.get(key, {}).items() if exp > now}
        self._sets[key] = live
        return set(live)

    def setnx(self, key: str, ttl_seconds: int) -> bool:
        self._check()
        now = self._clock()
        exp = self._keys.get(key)
        if exp is not None and exp > now:
            return False
        self._keys[key] = now + timedelta(seconds=ttl_seconds)
        return True


class Coordinator:
    def __init__(self, backend: InMemoryBackend, *, pause_passive_on_loss: bool = True) -> None:
        self._backend = backend
        self._pause_passive = pause_passive_on_loss

    # -- admission ----------------------------------------------------------

    def admit(self, capability_tier: str) -> Admission:
        """Whether new work of this tier may start given backend health."""
        if self._backend.connected:
            return Admission.ADMIT
        if capability_tier in PASSIVE_TIERS and self._pause_passive:
            return Admission.PAUSE
        return Admission.DENY                       # fail closed for active work

    # -- rate buckets -------------------------------------------------------

    def rate_allow(self, key: str, limit: int, window_seconds: int) -> bool:
        try:
            return self._backend.incr_window(key, window_seconds) <= limit
        except CoordUnavailable:
            return False                            # fail closed

    # -- concurrency semaphores ---------------------------------------------

    def acquire(self, key: str, limit: int, holder: str, ttl_seconds: int = 300) -> bool:
        try:
            members = self._backend.members(key)
            if holder in members:
                return True                         # idempotent re-acquire
            if len(members) >= limit:
                return False
            self._backend.sadd(key, holder, ttl_seconds)
            return True
        except CoordUnavailable:
            return False                            # fail closed

    def release(self, key: str, holder: str) -> None:
        try:
            self._backend.srem(key, holder)
        except CoordUnavailable:
            pass                                    # PG remains the source of truth

    def held(self, key: str) -> int:
        try:
            return len(self._backend.members(key))
        except CoordUnavailable:
            return 0

    def reconcile(self, key: str, durable_holders, ttl_seconds: int = 300) -> set[str]:
        """Rebuild a semaphore from durable leases after a coordination outage.

        Only the ephemeral membership is rebuilt; reservations are never touched
        here, so nothing is double-finalized.
        """
        durable = set(durable_holders)
        for member in self._backend.members(key) - durable:
            self._backend.srem(key, member)         # drop stale ephemeral holders
        for holder in durable:
            self._backend.sadd(key, holder, ttl_seconds)
        return self._backend.members(key)

    # -- cancellation broadcast ---------------------------------------------

    def broadcast_cancel(self, scope: str, ttl_seconds: int = 3600) -> None:
        try:
            self._backend.sadd("cancel", scope, ttl_seconds)
        except CoordUnavailable:
            pass

    def is_cancelled(self, scope: str) -> bool:
        try:
            return scope in self._backend.members("cancel")
        except CoordUnavailable:
            return True                             # cannot disprove a kill -> stop

    # -- short-lived dedup --------------------------------------------------

    def is_duplicate(self, key: str, ttl_seconds: int = 60) -> bool:
        try:
            return not self._backend.setnx(key, ttl_seconds)
        except CoordUnavailable:
            return False        # best-effort only; PG idempotency guards terminal state
