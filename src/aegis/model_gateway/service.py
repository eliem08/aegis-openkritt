"""Authenticated internal HTTP service for budgeted model calls."""

from __future__ import annotations

import hmac
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException

from aegis.ai.pricing import DEEPSEEK_V4_FLASH_PRICE, ModelPrice

from .budget import AtomicModelBudget, ModelBudgetError
from .cache import ExactModelCache
from .config import ModelGatewayConfig
from .models import ModelGatewayRequest, ModelGatewayResponse
from .provider import DeepSeekProvider, ProviderError


def _maximum_input_tokens(request: ModelGatewayRequest) -> int:
    content_bytes = sum(len(message.content.encode("utf-8")) for message in request.messages)
    return content_bytes + 1024 + 16 * len(request.messages)


def create_model_gateway_app(
    config: ModelGatewayConfig,
    *,
    provider: DeepSeekProvider | None = None,
    cache: ExactModelCache | None = None,
    budget: AtomicModelBudget | None = None,
    price: ModelPrice = DEEPSEEK_V4_FLASH_PRICE,
    day_provider=lambda: datetime.now(timezone.utc).date().isoformat(),
) -> FastAPI:
    model_provider = provider or DeepSeekProvider(config)

    @asynccontextmanager
    async def lifespan(_app):
        yield
        model_provider.close()

    app = FastAPI(
        title="aegis model gateway",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    result_cache = cache or ExactModelCache(config.cache_ttl)
    cost_budget = budget or AtomicModelBudget()

    def authorize(authorization: str | None) -> None:
        expected = f"Bearer {config.caller_token}"
        if authorization is None or not hmac.compare_digest(authorization, expected):
            raise HTTPException(status_code=401, detail="unauthorized")

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.post("/v1/completions", response_model=ModelGatewayResponse)
    def complete(
        request: ModelGatewayRequest,
        authorization: str | None = Header(default=None),
    ):
        authorize(authorization)
        cached = result_cache.get(request)
        if cached is not None:
            return cached

        reservation_id = f"{request.tenant_id}:{request.engagement_id}:{request.task_id}"
        maximum = price.reserve_maximum(
            _maximum_input_tokens(request), request.max_tokens,
        )
        try:
            cost_budget.reserve(
                reservation_id,
                tenant_id=request.tenant_id,
                cycle_id=request.budget_id,
                day=day_provider(),
                maximum=maximum,
            )
        except ModelBudgetError as exc:
            raise HTTPException(status_code=402, detail=str(exc)) from None

        try:
            response = model_provider.complete(request)
        except ProviderError as exc:
            cost_budget.release(reservation_id)
            status = 429 if exc.code == "rate_limited" else 503
            raise HTTPException(status_code=status, detail=exc.code) from None

        try:
            cost_budget.finalize(reservation_id, price.cost(response.usage, peak=True))
        except ModelBudgetError:
            raise HTTPException(status_code=503, detail="budget_reconciliation_failed") from None
        result_cache.put(request, response)
        return response

    return app
