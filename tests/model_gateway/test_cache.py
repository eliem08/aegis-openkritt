from aegis.model_gateway import (
    ExactModelCache,
    GatewayMessage,
    ModelGatewayRequest,
    ModelGatewayResponse,
)


def _request(tenant="tenant-a", content="one"):
    return ModelGatewayRequest(
        tenant_id=tenant,
        engagement_id="eng-1",
        task_id="task-1",
        budget_id="budget-1",
        messages=[GatewayMessage(role="user", content=content)],
    )


def test_cache_is_exact_and_tenant_partitioned():
    now = [10.0]
    cache = ExactModelCache(30, clock=lambda: now[0])
    request = _request()
    response = ModelGatewayResponse(content="result", model="deepseek-v4-flash", latency_ms=25)
    cache.put(request, response)

    hit = cache.get(request)
    assert hit is not None and hit.content == "result" and hit.cache_hit is True
    assert hit.latency_ms == 0
    assert cache.get(_request(content="two")) is None
    assert cache.get(_request(tenant="tenant-b")) is None

    now[0] = 41.0
    assert cache.get(request) is None


def test_key_contains_no_prompt_or_identifier_plaintext():
    request = _request(tenant="private-tenant", content="private-source-secret")
    key = ExactModelCache().key(request)
    assert len(key) == 64
    assert "private" not in key
