"""Cross-replica model-cost reservations using atomic Redis Lua scripts."""

from __future__ import annotations

from decimal import Decimal, ROUND_CEILING

from .budget import CostReservation, ModelBudgetError

NANODOLLARS = Decimal(1_000_000_000)

RESERVE_SCRIPT = """
local existing = redis.call('HGET', KEYS[3], 'reserved')
if existing then
  if existing ~= ARGV[1] then return -2 end
  local state = redis.call('HGET', KEYS[3], 'state')
  if state == 'reserved' then return 2 end
  return -5
end
local cycle = tonumber(redis.call('GET', KEYS[1]) or '0')
local daily = tonumber(redis.call('GET', KEYS[2]) or '0')
local amount = tonumber(ARGV[1])
if cycle + amount > tonumber(ARGV[2]) then return -3 end
if daily + amount > tonumber(ARGV[3]) then return -4 end
redis.call('INCRBY', KEYS[1], amount)
redis.call('INCRBY', KEYS[2], amount)
redis.call('EXPIRE', KEYS[1], ARGV[4])
redis.call('EXPIRE', KEYS[2], ARGV[5])
redis.call('HSET', KEYS[3], 'reserved', ARGV[1], 'actual', '', 'state', 'reserved',
  'tenant', ARGV[6], 'cycle', ARGV[7], 'day', ARGV[8],
  'cycle_key', KEYS[1], 'day_key', KEYS[2])
redis.call('EXPIRE', KEYS[3], ARGV[5])
return 1
"""

FINALIZE_SCRIPT = """
local reserved = redis.call('HGET', KEYS[1], 'reserved')
if not reserved then return -1 end
local state = redis.call('HGET', KEYS[1], 'state')
local prior = redis.call('HGET', KEYS[1], 'actual')
if state == 'finalized' then
  if prior == ARGV[1] then return 2 else return -2 end
end
local actual = tonumber(ARGV[1])
if actual > tonumber(reserved) then return -3 end
local release = tonumber(reserved) - actual
local cycle_key = redis.call('HGET', KEYS[1], 'cycle_key')
local day_key = redis.call('HGET', KEYS[1], 'day_key')
if release > 0 then
  redis.call('DECRBY', cycle_key, release)
  redis.call('DECRBY', day_key, release)
end
redis.call('HSET', KEYS[1], 'actual', ARGV[1], 'state', 'finalized')
redis.call('EXPIRE', KEYS[1], ARGV[2])
return 1
"""


def _nanos(value: Decimal) -> int:
    if value < 0:
        raise ValueError("model cost cannot be negative")
    return int((value * NANODOLLARS).to_integral_value(rounding=ROUND_CEILING))


def _dollars(value) -> Decimal:
    return Decimal(int(value or 0)) / NANODOLLARS


class RedisModelBudget:
    def __init__(
        self,
        client,
        *,
        namespace: str = "aegis-prod:model-cost",
        cycle_limit: Decimal = Decimal("2"),
        daily_limit: Decimal = Decimal("10"),
        reservation_ttl: int = 172800,
    ) -> None:
        prefix = namespace.strip(" :")
        if not prefix:
            raise ValueError("model budget namespace cannot be empty")
        self._client = client
        self._prefix = prefix
        self._cycle_limit = _nanos(cycle_limit)
        self._daily_limit = _nanos(daily_limit)
        self._ttl = reservation_ttl

    def _keys(self, tenant_id: str, cycle_id: str, day: str, reservation_id: str):
        safe = (tenant_id, cycle_id, day, reservation_id)
        if any(not value or any(c in value for c in "\r\n\x00{}") for value in safe):
            raise ValueError("invalid model budget identifier")
        tag = tenant_id
        return (
            f"{self._prefix}:{{{tag}}}:cycle:{cycle_id}",
            f"{self._prefix}:{{{tag}}}:day:{day}",
            f"{self._prefix}:{{{tag}}}:reservation:{reservation_id}",
        )

    def reserve(
        self,
        reservation_id: str,
        *,
        tenant_id: str,
        cycle_id: str,
        day: str,
        maximum: Decimal,
    ) -> CostReservation:
        cycle_key, day_key, reservation_key = self._keys(
            tenant_id, cycle_id, day, reservation_id,
        )
        amount = _nanos(maximum)
        try:
            code = int(self._client.eval(
                RESERVE_SCRIPT,
                3,
                cycle_key,
                day_key,
                reservation_key,
                amount,
                self._cycle_limit,
                self._daily_limit,
                172800,
                self._ttl,
                tenant_id,
                cycle_id,
                day,
            ))
        except Exception as exc:
            raise ModelBudgetError("redis_budget_unavailable") from exc
        errors = {
            -2: "reservation_conflict",
            -3: "cycle_budget_exhausted",
            -4: "daily_budget_exhausted",
            -5: "reservation_already_finalized",
        }
        if code in errors:
            raise ModelBudgetError(errors[code])
        return CostReservation(reservation_id, tenant_id, cycle_id, day, _dollars(amount))

    def finalize(
        self, reservation_id: str, actual: Decimal, *, tenant_id: str | None = None,
    ) -> CostReservation:
        if not tenant_id or any(c in tenant_id for c in "\r\n\x00{}"):
            raise ModelBudgetError("tenant_identity_required")
        key = f"{self._prefix}:{{{tenant_id}}}:reservation:{reservation_id}"
        actual_nanos = _nanos(actual)
        try:
            code = int(self._client.eval(FINALIZE_SCRIPT, 1, key, actual_nanos, self._ttl))
            data = self._client.hgetall(key)
        except Exception as exc:
            raise ModelBudgetError("redis_budget_unavailable") from exc
        errors = {-1: "reservation_missing", -2: "finalize_conflict", -3: "actual_exceeds_reservation"}
        if code in errors:
            raise ModelBudgetError(errors[code])
        return CostReservation(
            reservation_id,
            str(data["tenant"]),
            str(data["cycle"]),
            str(data["day"]),
            _dollars(data["reserved"]),
            _dollars(data["actual"]),
            "finalized",
        )

    def release(
        self, reservation_id: str, *, tenant_id: str | None = None,
    ) -> CostReservation:
        return self.finalize(reservation_id, Decimal(0), tenant_id=tenant_id)

    def health(self) -> bool:
        try:
            return bool(self._client.ping())
        except Exception as exc:
            raise ModelBudgetError("redis_budget_unavailable") from exc

    def spent(self, tenant_id: str, *, cycle_id: str | None = None, day: str | None = None):
        if cycle_id is not None:
            key = f"{self._prefix}:{{{tenant_id}}}:cycle:{cycle_id}"
        elif day is not None:
            key = f"{self._prefix}:{{{tenant_id}}}:day:{day}"
        else:
            raise ValueError("cycle_id or day is required")
        try:
            return _dollars(self._client.get(key))
        except Exception as exc:
            raise ModelBudgetError("redis_budget_unavailable") from exc
