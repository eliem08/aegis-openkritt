from decimal import Decimal

from aegis.ai.pricing import DEEPSEEK_V4_FLASH_PRICE
from aegis.model_gateway.models import ModelUsage


def test_flash_price_uses_cache_categories_and_peak_multiplier():
    usage = ModelUsage(
        prompt_tokens=1_000_000,
        prompt_cache_hit_tokens=500_000,
        prompt_cache_miss_tokens=500_000,
        completion_tokens=100_000,
        total_tokens=1_100_000,
    )
    regular = DEEPSEEK_V4_FLASH_PRICE.cost(usage, peak=False)
    assert regular == Decimal("0.0994")
    assert DEEPSEEK_V4_FLASH_PRICE.cost(usage, peak=True) == Decimal("0.1988")


def test_uncategorized_input_is_charged_as_cache_miss():
    usage = ModelUsage(prompt_tokens=1_000_000, total_tokens=1_000_000)
    assert DEEPSEEK_V4_FLASH_PRICE.cost(usage, peak=False) == Decimal("0.14")


def test_reservation_assumes_peak_and_cache_miss():
    assert DEEPSEEK_V4_FLASH_PRICE.reserve_maximum(1_000_000, 100_000) == Decimal("0.336")
