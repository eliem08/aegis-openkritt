"""Spend tracking + daily budget cap."""

from __future__ import annotations

from aegis.ai.cost import CostTracker


def _usage(pt, ct):
    return {"prompt_tokens": pt, "completion_tokens": ct, "total_tokens": pt + ct,
            "prompt_cache_miss_tokens": pt}


def test_records_cost_and_calls(tmp_path):
    t = CostTracker(state_path=tmp_path / "c.json")
    t.record(_usage(1_000_000, 1_000_000))     # 1M in + 1M out
    snap = t.snapshot()
    assert snap["day_calls"] == 1 and snap["total_calls"] == 1
    # 1M miss-input @0.14 + 1M output @0.28 = 0.42 (peak=False)
    assert abs(snap["day_cost"] - 0.42) < 0.01


def test_empty_usage_is_ignored(tmp_path):
    t = CostTracker(state_path=tmp_path / "c.json")
    t.record({})
    assert t.snapshot()["day_calls"] == 0


def test_over_budget_respects_cap(tmp_path, monkeypatch):
    t = CostTracker(state_path=tmp_path / "c.json")
    monkeypatch.setenv("AEGIS_DAILY_BUDGET_USD", "0.10")
    assert not t.over_budget()
    t.record(_usage(1_000_000, 0))             # 0.14 > 0.10
    assert t.over_budget()


def test_no_cap_means_never_over(tmp_path, monkeypatch):
    t = CostTracker(state_path=tmp_path / "c.json")
    monkeypatch.delenv("AEGIS_DAILY_BUDGET_USD", raising=False)
    t.record(_usage(9_000_000, 9_000_000))
    assert not t.over_budget()


def test_state_persists(tmp_path):
    p = tmp_path / "c.json"
    CostTracker(state_path=p).record(_usage(500_000, 0))
    t2 = CostTracker(state_path=p)             # reload same UTC day
    assert t2.snapshot()["total_calls"] == 1
