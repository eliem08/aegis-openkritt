"""Strict, versioned request/response contracts for the model gateway."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

Identifier = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$"),
]


class GatewayMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    role: Literal["system", "user", "assistant"]
    content: Annotated[str, StringConstraints(min_length=1, max_length=250_000)]


class ModelGatewayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    contract_version: Literal[1] = 1
    tenant_id: Identifier
    engagement_id: Identifier
    task_id: Identifier
    budget_id: Identifier
    messages: list[GatewayMessage] = Field(min_length=1, max_length=128)
    model: Literal["deepseek-v4-flash"] = "deepseek-v4-flash"
    json_mode: bool = True
    thinking: Literal["enabled", "disabled"] = "enabled"
    reasoning_effort: Literal["low", "high", "max"] = "high"
    max_tokens: int = Field(default=4096, ge=1, le=384_000)
    temperature: float = Field(default=0.2, ge=0, le=2)
    cache_allowed: bool = True


class ModelUsage(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)
    prompt_cache_hit_tokens: int = Field(default=0, ge=0)
    prompt_cache_miss_tokens: int = Field(default=0, ge=0)


class ModelGatewayResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    contract_version: Literal[1] = 1
    content: str
    model: str
    usage: ModelUsage = Field(default_factory=ModelUsage)
    cache_hit: bool = False
    latency_ms: int = Field(default=0, ge=0)
    request_id: str = Field(default="", max_length=256)
