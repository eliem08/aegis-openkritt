from decimal import Decimal

from fastapi.testclient import TestClient

from aegis.model_gateway import GatewayMessage, ModelGatewayConfig, ModelGatewayRequest
from aegis.model_gateway.budget import AtomicModelBudget, ModelBudgetError
from aegis.model_gateway.models import ModelGatewayResponse, ModelUsage
from aegis.model_gateway.service import create_model_gateway_app


class Provider:
    def __init__(self):
        self.calls = 0

    def complete(self, request):
        self.calls += 1
        return ModelGatewayResponse(
            content='{"finding":null}', model=request.model, request_id="provider-123",
            usage=ModelUsage(
                prompt_tokens=100, prompt_cache_miss_tokens=100,
                completion_tokens=10, total_tokens=110,
            ),
        )

    def close(self):
        pass


class Ledger:
    def __init__(self, reserve_error=False):
        self.reserve_error = reserve_error
        self.reservations = []
        self.finalizations = []
        self.closed = False

    def reserve(self, reservation_id, **metadata):
        if self.reserve_error:
            raise ModelBudgetError("usage_ledger_unavailable")
        self.reservations.append((reservation_id, metadata))

    def finalize(self, reservation_id, actual, **metadata):
        self.finalizations.append((reservation_id, actual, metadata))

    def close(self):
        self.closed = True


def body():
    return ModelGatewayRequest(
        tenant_id="tenant", engagement_id="engagement", task_id="task",
        budget_id="cycle", cache_allowed=False,
        messages=[GatewayMessage(role="user", content="return JSON")],
    ).model_dump(mode="json")


def test_usage_is_reserved_before_spend_and_finalized_with_provider_metadata():
    provider = Provider()
    ledger = Ledger()
    budget = AtomicModelBudget()
    app = create_model_gateway_app(
        ModelGatewayConfig("provider-secret", "x" * 48), provider=provider,
        budget=budget, ledger=ledger, day_provider=lambda: "2026-08-03",
    )
    with TestClient(app) as client:
        response = client.post(
            "/v1/completions", headers={"authorization": f"Bearer {'x' * 48}"},
            json=body(),
        )
    assert response.status_code == 200
    assert provider.calls == 1
    assert ledger.reservations[0][1]["price_version"] == "2026-08-03"
    assert ledger.reservations[0][1]["model"] == "deepseek-v4-flash"
    assert ledger.finalizations[0][2]["provider_request_id"] == "provider-123"
    assert ledger.finalizations[0][2]["usage"].total_tokens == 110
    assert ledger.closed is True


def test_usage_ledger_outage_prevents_paid_provider_call_and_releases_budget():
    provider = Provider()
    ledger = Ledger(reserve_error=True)
    budget = AtomicModelBudget()
    app = create_model_gateway_app(
        ModelGatewayConfig("provider-secret", "x" * 48), provider=provider,
        budget=budget, ledger=ledger, day_provider=lambda: "2026-08-03",
    )
    with TestClient(app) as client:
        response = client.post(
            "/v1/completions", headers={"authorization": f"Bearer {'x' * 48}"},
            json=body(),
        )
    assert response.status_code == 503
    assert response.json() == {"detail": "usage_ledger_unavailable"}
    assert provider.calls == 0
    assert budget.spent("tenant", cycle_id="cycle") == Decimal("0")
