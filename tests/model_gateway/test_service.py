from fastapi.testclient import TestClient

from aegis.model_gateway import (
    ExactModelCache,
    GatewayMessage,
    ModelGatewayConfig,
    ModelGatewayRequest,
    ModelGatewayResponse,
)
from aegis.model_gateway.provider import ProviderError
from aegis.model_gateway.service import create_model_gateway_app


class _Provider:
    def __init__(self, error=None):
        self.calls = 0
        self.error = error
        self.closed = False

    def complete(self, request):
        self.calls += 1
        if self.error:
            raise self.error
        return ModelGatewayResponse(content='{"ok":true}', model=request.model, latency_ms=7)

    def close(self):
        self.closed = True


def _body():
    return ModelGatewayRequest(
        tenant_id="tenant-a",
        engagement_id="eng-1",
        task_id="task-1",
        budget_id="budget-1",
        messages=[GatewayMessage(role="user", content="return json")],
    ).model_dump(mode="json")


def _app(provider):
    cfg = ModelGatewayConfig("provider-secret", "x" * 48)
    return create_model_gateway_app(cfg, provider=provider, cache=ExactModelCache(60))


def test_service_requires_internal_bearer_and_caches_exact_calls():
    provider = _Provider()
    with TestClient(_app(provider)) as client:
        assert client.get("/healthz").status_code == 200
        assert client.post("/v1/completions", json=_body()).status_code == 401
        headers = {"authorization": f"Bearer {'x' * 48}"}
        first = client.post("/v1/completions", headers=headers, json=_body())
        second = client.post("/v1/completions", headers=headers, json=_body())
    assert first.status_code == 200 and first.json()["cache_hit"] is False
    assert second.status_code == 200 and second.json()["cache_hit"] is True
    assert provider.calls == 1
    assert provider.closed is True


def test_service_sanitizes_provider_error():
    provider = _Provider(ProviderError("provider_unavailable"))
    with TestClient(_app(provider)) as client:
        response = client.post(
            "/v1/completions",
            headers={"authorization": f"Bearer {'x' * 48}"},
            json=_body(),
        )
    assert response.status_code == 503
    assert response.json() == {"detail": "provider_unavailable"}
