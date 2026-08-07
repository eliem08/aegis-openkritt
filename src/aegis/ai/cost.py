"""Spend tracking + daily budget cap for the paid LLM calls.

The 24/7 hunt does thousands of DeepSeek/OpenRouter calls per sweep with real money
attached. This aggregates per-call token usage (already returned by the client) into a
per-UTC-day and cumulative dollar figure using the versioned pricing table, persists it so
it survives restarts, and exposes a hard daily cap: when AEGIS_DAILY_BUDGET_USD is set and
today's spend reaches it, ``over_budget()`` goes true and the hunt loop pauses.

Thread-safe (the hunt runs in background threads). Cost is an ESTIMATE from list pricing —
close, not a billing statement.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from .pricing import DEEPSEEK_V4_FLASH_PRICE


def _today() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


class CostTracker:
    def __init__(self, *, price=DEEPSEEK_V4_FLASH_PRICE,
                 state_path: str | Path = "reports/cost_state.json") -> None:
        self._price = price
        self._lock = threading.Lock()
        self._path = Path(state_path)
        self._day = _today()
        self._day_cost = Decimal(0)
        self._day_calls = 0
        self._day_tokens = 0
        self._total_cost = Decimal(0)
        self._total_calls = 0
        self._load()

    def _load(self) -> None:
        if not self._path.is_file():
            return
        try:
            d = json.loads(self._path.read_text(encoding="utf-8"))
        except Exception:
            return
        self._total_cost = Decimal(str(d.get("total_cost", "0")))
        self._total_calls = int(d.get("total_calls", 0))
        if d.get("day") == self._day:               # same UTC day -> resume today's tally
            self._day_cost = Decimal(str(d.get("day_cost", "0")))
            self._day_calls = int(d.get("day_calls", 0))
            self._day_tokens = int(d.get("day_tokens", 0))

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps({
                "day": self._day, "day_cost": str(self._day_cost),
                "day_calls": self._day_calls, "day_tokens": self._day_tokens,
                "total_cost": str(self._total_cost), "total_calls": self._total_calls,
            }, indent=1), encoding="utf-8")
        except Exception:
            pass

    def _rollover(self) -> None:
        t = _today()
        if t != self._day:
            self._day = t
            self._day_cost = Decimal(0)
            self._day_calls = 0
            self._day_tokens = 0

    def _cost_of(self, usage: dict) -> Decimal:
        # Prefer the provider's EXACT cost when present (OpenRouter returns usage.cost in USD) —
        # more accurate than recomputing from tokens against a fixed price table.
        exact = usage.get("cost")
        if isinstance(exact, (int, float)) and not isinstance(exact, bool) and exact > 0:
            return Decimal(str(exact))
        pt = int(usage.get("prompt_tokens", 0) or 0)
        ct = int(usage.get("completion_tokens", 0) or 0)
        hit = int(usage.get("prompt_cache_hit_tokens", 0) or 0)
        miss = int(usage.get("prompt_cache_miss_tokens", 0) or 0)
        try:
            from aegis.model_gateway.models import ModelUsage
            mu = ModelUsage(prompt_tokens=pt, completion_tokens=ct, total_tokens=pt + ct,
                            prompt_cache_hit_tokens=hit, prompt_cache_miss_tokens=miss)
            return self._price.cost(mu, peak=False)
        except Exception:
            # fallback: treat all prompt tokens as cache-miss input
            return (Decimal(pt) * self._price.cache_miss_input_per_million
                    + Decimal(ct) * self._price.output_per_million) / Decimal(1_000_000)

    def record(self, usage: dict) -> None:
        if not usage:
            return
        c = self._cost_of(usage)
        with self._lock:
            self._rollover()
            self._day_cost += c
            self._day_calls += 1
            self._day_tokens += int(usage.get("total_tokens", 0) or 0)
            self._total_cost += c
            self._total_calls += 1
            self._save()

    def daily_cap(self) -> Decimal:
        raw = os.environ.get("AEGIS_DAILY_BUDGET_USD", "").strip()
        try:
            return Decimal(raw) if raw else Decimal(0)
        except Exception:
            return Decimal(0)

    def over_budget(self) -> bool:
        cap = self.daily_cap()
        with self._lock:
            self._rollover()
            return cap > 0 and self._day_cost >= cap

    def snapshot(self) -> dict:
        cap = self.daily_cap()
        with self._lock:
            self._rollover()
            return {
                "day": self._day,
                "day_cost": round(float(self._day_cost), 4),
                "day_calls": self._day_calls,
                "day_tokens": self._day_tokens,
                "total_cost": round(float(self._total_cost), 4),
                "total_calls": self._total_calls,
                "daily_cap": round(float(cap), 2),
                "over_budget": cap > 0 and self._day_cost >= cap,
            }


#: process-wide singleton the client records into
TRACKER = CostTracker()
