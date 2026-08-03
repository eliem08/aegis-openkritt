"""Versioned Decimal pricing for DeepSeek token usage."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from aegis.model_gateway.models import ModelUsage

MILLION = Decimal(1_000_000)


@dataclass(frozen=True)
class ModelPrice:
    model: str
    version: str
    cache_hit_input_per_million: Decimal
    cache_miss_input_per_million: Decimal
    output_per_million: Decimal
    peak_multiplier: Decimal = Decimal("2")

    def cost(self, usage: ModelUsage, *, peak: bool = True) -> Decimal:
        hit = Decimal(usage.prompt_cache_hit_tokens)
        miss = Decimal(usage.prompt_cache_miss_tokens)
        categorized = hit + miss
        if categorized < usage.prompt_tokens:
            miss += Decimal(usage.prompt_tokens) - categorized
        total = (
            hit * self.cache_hit_input_per_million
            + miss * self.cache_miss_input_per_million
            + Decimal(usage.completion_tokens) * self.output_per_million
        ) / MILLION
        return total * (self.peak_multiplier if peak else Decimal(1))

    def reserve_maximum(self, input_tokens: int, output_tokens: int) -> Decimal:
        usage = ModelUsage(
            prompt_tokens=max(0, input_tokens),
            prompt_cache_miss_tokens=max(0, input_tokens),
            completion_tokens=max(0, output_tokens),
            total_tokens=max(0, input_tokens) + max(0, output_tokens),
        )
        return self.cost(usage, peak=True)


DEEPSEEK_V4_FLASH_PRICE = ModelPrice(
    model="deepseek-v4-flash",
    version="2026-08-03",
    cache_hit_input_per_million=Decimal("0.0028"),
    cache_miss_input_per_million=Decimal("0.14"),
    output_per_million=Decimal("0.28"),
)
