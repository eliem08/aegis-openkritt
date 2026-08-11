from dataclasses import replace
from decimal import Decimal

from aegis.effectiveness.metrics import calculate_metrics
from aegis.effectiveness.models import FactType, OutcomeState
from aegis.effectiveness.report import render_json, render_markdown
from aegis.effectiveness.repository import SQLiteEffectivenessRepository
from aegis.effectiveness.shadow import ShadowCandidate, build_shadow_batch

from .helpers import fact, outcome, subject


def test_metrics_preserve_unknown_money_and_distinguish_outcomes(tmp_path):
    repository = SQLiteEffectivenessRepository(tmp_path / "ledger.db")
    first = subject(1)
    second = subject(2)
    repository.record_subject(first, (
        fact(first), fact(first, FactType.FINDING_REPRODUCED),
        fact(first, FactType.SKEPTIC_TRIAGE_SURVIVED),
        fact(first, FactType.REPORT_HUMAN_APPROVED), fact(first, FactType.REPORT_SUBMITTED),
    ))
    repository.record_subject(second, (fact(second), fact(second, FactType.REPORT_SUBMITTED)))
    repository.record_outcome(outcome(first, state=OutcomeState.ACCEPTED, bounty=Decimal("100")))
    repository.record_outcome(outcome(
        second, state=OutcomeState.DUPLICATE, bounty=None, key="outcome:second",
    ))
    metrics = calculate_metrics(repository)
    overall = metrics.overall
    assert (overall.opportunities, overall.reproduced, overall.submitted) == (2, 1, 2)
    assert (overall.accepted, overall.duplicates, overall.externally_resolved) == (1, 1, 2)
    assert overall.acceptance_rate == 0.5 and overall.duplicate_rate == 0.5
    assert overall.unknown_bounty_outcomes == 1
    assert overall.realized_profit_usd is None
    assert overall.known_realized_profit_usd == Decimal("92.50")
    assert '"realized_profit_usd": null' in render_json(metrics, authoritative=False)
    assert "Unknown bounty values remain unknown" in render_markdown(metrics, authoritative=False)
    repository.close()


def test_rejected_is_not_silently_added_to_external_denominator(tmp_path):
    repository = SQLiteEffectivenessRepository(tmp_path / "ledger.db")
    item = subject()
    repository.record_subject(item, (fact(item),))
    rejected = outcome(item, state=OutcomeState.REJECTED, bounty=None)
    rejected = replace(rejected, submitted_at=None)
    repository.record_outcome(rejected)
    metrics = calculate_metrics(repository).overall
    assert metrics.rejected == 1 and metrics.externally_resolved == 0
    assert metrics.acceptance_rate is None and metrics.duplicate_rate is None
    repository.close()


def test_shadow_ranking_falls_back_until_calibration_eligible(tmp_path):
    repository = SQLiteEffectivenessRepository(tmp_path / "ledger.db")
    batch = build_shadow_batch(repository, (
        ShadowCandidate("a", "authorization-boundary", Decimal("10")),
        ShadowCandidate("b", "xss", Decimal("5")),
    ), batch_id="batch-1", idempotency_key="shadow-1")
    assert all(entry.fallback_reason for entry in batch.entries)
    assert [item.opportunity_id for item in sorted(batch.entries, key=lambda item: item.learned_rank)] == [
        "a", "b",
    ]
    assert repository.record_shadow_batch(batch)
    assert not repository.record_shadow_batch(batch)
    repository.close()


def test_shadow_uses_real_economics_only_at_thirty_samples(tmp_path):
    repository = SQLiteEffectivenessRepository(tmp_path / "ledger.db")
    for index in range(30):
        item = subject(index, technique="authorization-boundary")
        repository.record_subject(item, (fact(item), fact(item, FactType.REPORT_SUBMITTED)))
        repository.record_outcome(outcome(item, bounty=Decimal("100"), key=f"outcome:{index}"))
    batch = build_shadow_batch(repository, (
        ShadowCandidate("auth", "authorization-boundary", Decimal("1")),
        ShadowCandidate("other", "xss", Decimal("10")),
    ), batch_id="batch-eligible", idempotency_key="shadow-eligible")
    auth = next(item for item in batch.entries if item.opportunity_id == "auth")
    assert auth.samples == 30 and auth.fallback_reason is None
    assert auth.learned_score > Decimal("10") and auth.learned_rank == 1
    repository.close()
