import pytest

from aegis.model_gateway import ModelGatewayConfig, ModelGatewayConfigError


BASE = {
    "AEGIS_MODEL_PROVIDER_KEY": "provider-secret",
    "AEGIS_MODEL_GATEWAY_TOKEN": "x" * 48,
}
REDIS = "redis://default:strong-secret@redis.prod.internal:6379/0"
POSTGRES = (
    "postgresql://svc:strong-secret@pg.prod.internal:5432/aegis"
    "?sslmode=verify-full&sslrootcert=/run/secrets/postgres_ca"
)


def test_production_requires_both_durable_ledgers():
    with pytest.raises(ModelGatewayConfigError, match="Redis and PostgreSQL"):
        ModelGatewayConfig.from_env({**BASE, "AEGIS_PRODUCTION": "1"})
    with pytest.raises(ModelGatewayConfigError, match="Redis and PostgreSQL"):
        ModelGatewayConfig.from_env({
            **BASE, "AEGIS_PRODUCTION": "1", "AEGIS_REDIS_URL": REDIS,
        })


def test_production_accepts_authenticated_ledgers_and_isolates_namespace():
    config = ModelGatewayConfig.from_env({
        **BASE,
        "AEGIS_PRODUCTION": "1",
        "AEGIS_REDIS_URL": REDIS,
        "AEGIS_DB_URL": POSTGRES,
        "AEGIS_MODEL_BUDGET_NAMESPACE": "tenant-platform:model-cost",
    })
    assert config.require_durable_budget is True
    assert config.budget_namespace == "tenant-platform:model-cost"


@pytest.mark.parametrize("url", [
    "redis://redis.prod.internal:6379/0",
    "http://default:secret@redis.prod.internal:6379/0",
    "redis://default:secret@/0",
])
def test_redis_budget_url_requires_supported_scheme_host_and_password(url):
    with pytest.raises(ModelGatewayConfigError, match="authenticated"):
        ModelGatewayConfig.from_env({**BASE, "AEGIS_REDIS_URL": url})


@pytest.mark.parametrize("url", [
    "postgresql://svc:secret@pg.prod.internal:5432/aegis",
    "postgresql://pg.prod.internal:5432/aegis?sslmode=verify-full",
    "http://svc:secret@pg.prod.internal/aegis?sslmode=verify-full",
])
def test_usage_ledger_requires_authenticated_verified_postgres(url):
    with pytest.raises(ModelGatewayConfigError, match="sslmode=verify-full"):
        ModelGatewayConfig.from_env({**BASE, "AEGIS_DB_URL": url})
