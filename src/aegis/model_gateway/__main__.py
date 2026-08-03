"""Run the dedicated model gateway."""

import uvicorn

from .config import ModelGatewayConfig
from .ledger import PostgresModelUsageLedger
from .redis_budget import RedisModelBudget
from .service import create_model_gateway_app


def factory():
    config = ModelGatewayConfig.from_env()
    budget = None
    ledger = None
    if config.redis_url:
        try:
            import redis

            client = redis.Redis.from_url(
                config.redis_url,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2,
                health_check_interval=30,
            )
            client.ping()
        except Exception as exc:
            raise RuntimeError("durable model budget storage is unavailable") from exc
        budget = RedisModelBudget(client, namespace=config.budget_namespace)
    if config.database_url:
        try:
            from psycopg_pool import ConnectionPool

            pool = ConnectionPool(config.database_url, min_size=1, max_size=4, timeout=5)
            ledger = PostgresModelUsageLedger(pool)
        except Exception as exc:
            close = getattr(locals().get("pool"), "close", None)
            if close is not None:
                close()
            raise RuntimeError("durable model usage ledger is unavailable") from exc
    return create_model_gateway_app(config, budget=budget, ledger=ledger)


def main() -> None:
    uvicorn.run(
        "aegis.model_gateway.__main__:factory",
        factory=True,
        host="0.0.0.0",
        port=8090,
        proxy_headers=False,
        server_header=False,
    )


if __name__ == "__main__":
    main()
