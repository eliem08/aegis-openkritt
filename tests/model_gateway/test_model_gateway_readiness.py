from fastapi.testclient import TestClient

from aegis.model_gateway import ModelGatewayConfig
from aegis.model_gateway.budget import AtomicModelBudget, ModelBudgetError
from aegis.model_gateway.service import create_model_gateway_app


class Provider:
    def close(self):
        pass


class Budget(AtomicModelBudget):
    def __init__(self, healthy=True):
        super().__init__()
        self.healthy = healthy

    def health(self):
        if not self.healthy:
            raise ModelBudgetError("redis_budget_unavailable")
        return True


class Ledger:
    def __init__(self, healthy=True):
        self.healthy = healthy

    def health(self):
        if not self.healthy:
            raise ModelBudgetError("usage_ledger_unavailable")
        return True

    def close(self):
        pass


def app(budget, ledger):
    return create_model_gateway_app(
        ModelGatewayConfig("provider-secret", "x" * 48),
        provider=Provider(), budget=budget, ledger=ledger,
    )


def test_readyz_requires_both_cost_dependencies():
    with TestClient(app(Budget(), Ledger())) as client:
        assert client.get("/healthz").status_code == 200
        assert client.get("/readyz").json() == {"status": "ready"}
    with TestClient(app(Budget(healthy=False), Ledger())) as client:
        response = client.get("/readyz")
        assert response.status_code == 503
        assert response.json() == {"detail": "dependencies_unavailable"}
    with TestClient(app(Budget(), Ledger(healthy=False))) as client:
        assert client.get("/readyz").status_code == 503
