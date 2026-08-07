"""Authenticated internal HTTP service for budgeted model calls."""

from __future__ import annotations

import hmac
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from decimal import Decimal

from fastapi import FastAPI, Header, HTTPException

from aegis.ai.pricing import DEEPSEEK_V4_FLASH_PRICE, ModelPrice

from .budget import AtomicModelBudget, ModelBudgetError
from .cache import ExactModelCache
from .config import ModelGatewayConfig
from .models import ModelGatewayRequest, ModelGatewayResponse, ModelUsage
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
    ledger=None,
    price: ModelPrice = DEEPSEEK_V4_FLASH_PRICE,
    day_provider=lambda: datetime.now(UTC).date().isoformat(),
) -> FastAPI:
    model_provider = provider or DeepSeekProvider(config)

    @asynccontextmanager
    async def lifespan(_app):
        yield
        model_provider.close()
        if ledger is not None:
            ledger.close()

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

    @app.get("/readyz")
    def readyz():
        try:
            budget_ready = getattr(cost_budget, "health", lambda: True)()
            ledger_ready = True if ledger is None else ledger.health()
        except ModelBudgetError:
            raise HTTPException(status_code=503, detail="dependencies_unavailable") from None
        if not budget_ready or not ledger_ready:
            raise HTTPException(status_code=503, detail="dependencies_unavailable")
        return {"status": "ready"}

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
        usage_day = day_provider()
        try:
            cost_budget.reserve(
                reservation_id,
                tenant_id=request.tenant_id,
                cycle_id=request.budget_id,
                day=usage_day,
                maximum=maximum,
            )
        except ModelBudgetError as exc:
            raise HTTPException(status_code=402, detail=str(exc)) from None

        if ledger is not None:
            try:
                ledger.reserve(
                    reservation_id,
                    tenant_id=request.tenant_id,
                    engagement_id=request.engagement_id,
                    cycle_id=request.budget_id,
                    day=usage_day,
                    model=request.model,
                    price_version=price.version,
                    maximum=maximum,
                )
            except ModelBudgetError:
                cost_budget.release(reservation_id, tenant_id=request.tenant_id)
                raise HTTPException(status_code=503, detail="usage_ledger_unavailable") from None

        try:
            response = model_provider.complete(request)
        except ProviderError as exc:
            reconciliation_failed = False
            if ledger is not None:
                try:
                    ledger.finalize(
                        reservation_id,
                        Decimal(0),
                        usage=ModelUsage(),
                        provider_request_id="",
                    )
                except ModelBudgetError:
                    reconciliation_failed = True
            try:
                cost_budget.release(reservation_id, tenant_id=request.tenant_id)
            except ModelBudgetError:
                reconciliation_failed = True
            if reconciliation_failed:
                raise HTTPException(status_code=503, detail="usage_reconciliation_failed") from None
            status = 429 if exc.code == "rate_limited" else 503
            raise HTTPException(status_code=status, detail=exc.code) from None

        actual = price.cost(response.usage, peak=True)
        try:
            if ledger is not None:
                ledger.finalize(
                    reservation_id,
                    actual,
                    usage=response.usage,
                    provider_request_id=response.request_id,
                )
            cost_budget.finalize(
                reservation_id,
                actual,
                tenant_id=request.tenant_id,
            )
        except ModelBudgetError:
            raise HTTPException(status_code=503, detail="usage_reconciliation_failed") from None
        result_cache.put(request, response)
        return response

    return app
