from decimal import Decimal

from fastapi.testclient import TestClient

from aegis.model_gateway import GatewayMessage, ModelGatewayConfig, ModelGatewayRequest
from aegis.model_gateway.budget import AtomicModelBudget
from aegis.model_gateway.models import ModelGatewayResponse, ModelUsage
from aegis.model_gateway.service import create_model_gateway_app


class _Provider:
    def __init__(self):
        self.calls = 0

    def complete(self, request):
        self.calls += 1
        return ModelGatewayResponse(
            content='{"ok":true}',
            model=request.model,
            usage=ModelUsage(
                prompt_tokens=100,
                prompt_cache_miss_tokens=100,
                completion_tokens=10,
                total_tokens=110,
            ),
        )

    def close(self):
        pass


def _body(task="task-1"):
    return ModelGatewayRequest(
        tenant_id="tenant-a",
        engagement_id="eng-1",
        task_id=task,
        budget_id="cycle-1",
        messages=[GatewayMessage(role="user", content="return json")],
        cache_allowed=False,
    ).model_dump(mode="json")


def test_service_reserves_and_reconciles_peak_cost():
    provider = _Provider()
    budget = AtomicModelBudget(cycle_limit=Decimal("2"), daily_limit=Decimal("10"))
    cfg = ModelGatewayConfig("provider-secret", "x" * 48)
    app = create_model_gateway_app(
        cfg, provider=provider, budget=budget, day_provider=lambda: "2026-08-03",
    )
    with TestClient(app) as client:
        response = client.post(
            "/v1/completions",
            headers={"authorization": f"Bearer {'x' * 48}"},
            json=_body(),
        )
    assert response.status_code == 200
    assert budget.spent("tenant-a", cycle_id="cycle-1") == Decimal("0.0000336")


def test_exhausted_budget_prevents_provider_call():
    provider = _Provider()
    budget = AtomicModelBudget(cycle_limit=Decimal("0"), daily_limit=Decimal("0"))
    cfg = ModelGatewayConfig("provider-secret", "x" * 48)
    app = create_model_gateway_app(cfg, provider=provider, budget=budget)
    with TestClient(app) as client:
        response = client.post(
            "/v1/completions",
            headers={"authorization": f"Bearer {'x' * 48}"},
            json=_body(),
        )
    assert response.status_code == 402
    assert response.json() == {"detail": "cycle_budget_exhausted"}
    assert provider.calls == 0
