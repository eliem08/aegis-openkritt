from __future__ import annotations

from decimal import Decimal

from aegis.effectiveness.policy import EconomicShadowCandidate, build_shadow_policy_batch
from aegis.effectiveness.repository import SQLiteEffectivenessRepository

from .helpers import subject


def candidate(index, *, selected=False):
    return EconomicShadowCandidate(
        opportunity_id=f"opportunity-{index}", program_id="program",
        asset_class="web_api", technique="authorization-boundary",
        weakness_family="authorization", existing_score=Decimal(100 - index),
        actual_selected=selected, estimated_hours=Decimal("1"),
        estimated_requests=10, estimated_compute_cost_usd=Decimal("1"),
    )


def test_shadow_policy_falls_back_without_real_economics_and_persists(tmp_path):
    repository = SQLiteEffectivenessRepository(tmp_path / "ledger.db")
    repository.record_subject(subject())
    batch = build_shadow_policy_batch(
        repository, (candidate(1, selected=True), candidate(2)), batch_id="batch-v2",
        idempotency_key="batch-v2", selection_count=1,
        computed_at="2026-08-11T00:00:00+00:00",
    )
    assert all(item.economics_status == "ECONOMICS_INCOMPLETE" for item in batch.entries)
    assert all(item.ev_usd is None for item in batch.entries)
    assert sum(bool(item.shadow_would_select) for item in batch.entries) == 1
    assert all(item.shadow_hypothetical_reward_usd is None for item in batch.entries)
    assert repository.record_shadow_batch(batch)
    assert not repository.record_shadow_batch(batch)
    assert repository.shadow_batches()[0] == batch
    repository.close()


def test_shadow_stop_loss_is_recommendation_only(tmp_path):
    repository = SQLiteEffectivenessRepository(tmp_path / "ledger.db")
    batch = build_shadow_policy_batch(
        repository, tuple(candidate(index) for index in range(1, 6)),
        batch_id="allocation", idempotency_key="allocation", selection_count=5,
        computed_at="2026-08-11T00:00:00+00:00",
    )
    assert sum(item.allocation_mode == "EXPLORE" for item in batch.entries) == 1
    assert sum(item.allocation_mode == "EXPLOIT" for item in batch.entries) == 4
    assert all(item.stop_loss_recommendation == "CONTINUE" for item in batch.entries)
    assert all(item.actual_realized_reward_usd is None for item in batch.entries)
    repository.close()
