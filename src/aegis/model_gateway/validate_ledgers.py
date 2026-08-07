"""Safe live validation for the model gateway's Redis and PostgreSQL ledgers."""

from __future__ import annotations

import argparse
import uuid
from decimal import Decimal
from pathlib import Path

from .budget import ModelBudgetError
from .ledger import PostgresModelUsageLedger
from .models import ModelUsage
from .redis_budget import RedisModelBudget


def _read(path: str) -> str:
    value = Path(path).read_text(encoding="utf-8").strip()
    if not value:
        raise RuntimeError("ledger credential file is empty")
    return value


def validate(redis_url: str, database_url: str) -> None:
    import redis
    from psycopg_pool import ConnectionPool

    marker = f"validation-{uuid.uuid4().hex}"
    tenant = marker
    namespace = f"aegis-validation:{marker}"
    redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
    pool = ConnectionPool(database_url, min_size=1, max_size=2, timeout=5)
    reservation_id = f"{tenant}:engagement:task"
    try:
        first = RedisModelBudget(
            redis_client, namespace=namespace,
            cycle_limit=Decimal(1), daily_limit=Decimal(1),
        )
        second = RedisModelBudget(
            redis_client, namespace=namespace,
            cycle_limit=Decimal(1), daily_limit=Decimal(1),
        )
        first.reserve(
            reservation_id, tenant_id=tenant, cycle_id="cycle", day="2026-08-03",
            maximum=Decimal("0.8"),
        )
        try:
            second.reserve(
                f"{tenant}:engagement:other", tenant_id=tenant, cycle_id="cycle",
                day="2026-08-03", maximum=Decimal("0.3"),
            )
        except ModelBudgetError as exc:
            if str(exc) != "cycle_budget_exhausted":
                raise
        else:
            raise RuntimeError("cross-instance budget ceiling was not enforced")
        second.finalize(reservation_id, Decimal("0.2"), tenant_id=tenant)
        if first.spent(tenant, cycle_id="cycle") != Decimal("0.2"):
            raise RuntimeError("Redis reconciliation mismatch")

        ledger = PostgresModelUsageLedger(pool)
        ledger.reserve(
            reservation_id, tenant_id=tenant, engagement_id="engagement",
            cycle_id="cycle", day="2026-08-03", model="deepseek-v4-flash",
            price_version="2026-08-03", maximum=Decimal("0.8"),
        )
        usage = ModelUsage(
            prompt_tokens=100, prompt_cache_miss_tokens=100,
            completion_tokens=10, total_tokens=110,
        )
        record = ledger.finalize(
            reservation_id, Decimal("0.2"), usage=usage,
            provider_request_id="validation-request",
        )
        if record.state != "finalized" or record.actual != Decimal("0.2"):
            raise RuntimeError("PostgreSQL usage finalization mismatch")
    finally:
        try:
            with pool.connection() as connection, connection.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM model_usage_reservations WHERE reservation_id=%s",
                    (reservation_id,),
                )
        finally:
            for key in redis_client.scan_iter(match=f"{namespace}:*"):
                redis_client.delete(key)
            pool.close()
            redis_client.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="validate durable model ledgers")
    parser.add_argument("--redis-file", required=True)
    parser.add_argument("--database-file", required=True)
    args = parser.parse_args()
    validate(_read(args.redis_file), _read(args.database_file))
    print("redis_budget=ok")
    print("postgres_usage_ledger=ok")


if __name__ == "__main__":
    main()
