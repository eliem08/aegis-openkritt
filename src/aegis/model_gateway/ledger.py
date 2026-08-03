"""Durable PostgreSQL audit ledger for every paid model reservation."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from .budget import ModelBudgetError
from .models import ModelUsage
from .redis_budget import _dollars, _nanos

SCHEMA = """
CREATE TABLE IF NOT EXISTS model_usage_reservations (
    reservation_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    cycle_id TEXT NOT NULL,
    usage_day TEXT NOT NULL,
    model TEXT NOT NULL,
    price_version TEXT NOT NULL,
    reserved_nanos BIGINT NOT NULL,
    actual_nanos BIGINT,
    state TEXT NOT NULL CHECK (state IN ('reserved', 'finalized')),
    provider_request_id TEXT NOT NULL DEFAULT '',
    prompt_tokens BIGINT NOT NULL DEFAULT 0,
    prompt_cache_hit_tokens BIGINT NOT NULL DEFAULT 0,
    prompt_cache_miss_tokens BIGINT NOT NULL DEFAULT 0,
    completion_tokens BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finalized_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_model_usage_tenant_day
    ON model_usage_reservations(tenant_id, usage_day);
"""


@dataclass(frozen=True)
class ModelUsageRecord:
    reservation_id: str
    tenant_id: str
    engagement_id: str
    cycle_id: str
    day: str
    model: str
    price_version: str
    reserved: Decimal
    actual: Decimal | None
    state: str


class PostgresModelUsageLedger:
    """Idempotent, replica-safe record of reservations and actual provider cost."""

    def __init__(self, pool) -> None:
        self._pool = pool
        self._exec(SCHEMA)

    def _exec(self, sql, params=()):
        try:
            with self._pool.connection() as connection, connection.cursor() as cursor:
                cursor.execute(sql, params)
        except ModelBudgetError:
            raise
        except Exception as exc:
            raise ModelBudgetError("usage_ledger_unavailable") from exc

    def _one(self, sql, params=()):
        try:
            with self._pool.connection() as connection, connection.cursor() as cursor:
                cursor.execute(sql, params)
                return cursor.fetchone()
        except Exception as exc:
            raise ModelBudgetError("usage_ledger_unavailable") from exc

    @staticmethod
    def _record(row) -> ModelUsageRecord:
        return ModelUsageRecord(
            reservation_id=row[0], tenant_id=row[1], engagement_id=row[2],
            cycle_id=row[3], day=row[4], model=row[5], price_version=row[6],
            reserved=_dollars(row[7]), actual=None if row[8] is None else _dollars(row[8]),
            state=row[9],
        )

    def get(self, reservation_id: str) -> ModelUsageRecord | None:
        row = self._one(
            "SELECT reservation_id,tenant_id,engagement_id,cycle_id,usage_day,model,"
            "price_version,reserved_nanos,actual_nanos,state "
            "FROM model_usage_reservations WHERE reservation_id=%s",
            (reservation_id,),
        )
        return None if row is None else self._record(row)

    def reserve(
        self, reservation_id: str, *, tenant_id: str, engagement_id: str,
        cycle_id: str, day: str, model: str, price_version: str, maximum: Decimal,
    ) -> ModelUsageRecord:
        self._exec(
            "INSERT INTO model_usage_reservations "
            "(reservation_id,tenant_id,engagement_id,cycle_id,usage_day,model,"
            "price_version,reserved_nanos,state) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'reserved') "
            "ON CONFLICT (reservation_id) DO NOTHING",
            (reservation_id, tenant_id, engagement_id, cycle_id, day, model,
             price_version, _nanos(maximum)),
        )
        record = self.get(reservation_id)
        expected = (tenant_id, engagement_id, cycle_id, day, model, price_version, maximum)
        actual = None if record is None else (
            record.tenant_id, record.engagement_id, record.cycle_id, record.day,
            record.model, record.price_version, record.reserved,
        )
        if actual != expected:
            raise ModelBudgetError("usage_reservation_conflict")
        return record

    def finalize(
        self, reservation_id: str, actual: Decimal, *, usage: ModelUsage,
        provider_request_id: str,
    ) -> ModelUsageRecord:
        if actual < 0:
            raise ValueError("actual model cost cannot be negative")
        self._exec(
            "UPDATE model_usage_reservations SET actual_nanos=%s,state='finalized',"
            "provider_request_id=%s,prompt_tokens=%s,prompt_cache_hit_tokens=%s,"
            "prompt_cache_miss_tokens=%s,completion_tokens=%s,finalized_at=NOW() "
            "WHERE reservation_id=%s AND state='reserved'",
            (_nanos(actual), provider_request_id[:256], usage.prompt_tokens,
             usage.prompt_cache_hit_tokens, usage.prompt_cache_miss_tokens,
             usage.completion_tokens, reservation_id),
        )
        record = self.get(reservation_id)
        if record is None:
            raise ModelBudgetError("usage_reservation_missing")
        if record.actual != _dollars(_nanos(actual)):
            raise ModelBudgetError("usage_finalize_conflict")
        return record

    def close(self) -> None:
        close = getattr(self._pool, "close", None)
        if close is not None:
            close()
