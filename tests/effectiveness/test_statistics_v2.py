from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

import pytest

from aegis.effectiveness.models import FactType, OutcomeState
from aegis.effectiveness.repository import SQLiteEffectivenessRepository
from aegis.effectiveness.statistics import (
    STATISTICAL_MODEL_VERSION,
    beta_estimate,
    calculate_profitability_profiles,
)

from .helpers import fact, outcome, subject


def test_beta_estimate_is_smoothed_versioned_and_confidence_gated():
    estimate = beta_estimate(1, 1, computed_at="2026-08-11T00:00:00+00:00")
    assert estimate.mean == pytest.approx(2 / 3)
    assert 0 <= estimate.lower <= estimate.mean <= estimate.upper <= 1
    assert estimate.sample_count == 1
    assert estimate.confidence_class.value == "INSUFFICIENT_DATA"
    assert estimate.model_version == STATISTICAL_MODEL_VERSION
    assert estimate.computed_at == "2026-08-11T00:00:00+00:00"


def test_profiles_are_program_local_and_do_not_guess_payout(tmp_path):
    repository = SQLiteEffectivenessRepository(tmp_path / "ledger.db")
    first = subject(1, technique="authorization-boundary")
    second = replace(
        subject(2, technique="authorization-boundary"), program_id="other-program",
    )
    repository.record_subject(first, (
        fact(first, FactType.CANDIDATE_GENERATED),
        fact(first, FactType.INDEPENDENTLY_VERIFIED),
        fact(first, FactType.SUBMITTED),
    ))
    repository.record_subject(second, (fact(second, FactType.CANDIDATE_GENERATED),))
    repository.record_outcome(outcome(first, state=OutcomeState.ACCEPTED))
    repository.record_outcome(outcome(
        second, state=OutcomeState.DUPLICATE, bounty=None, key="outcome:second",
    ))
    report = calculate_profitability_profiles(
        repository, computed_at="2026-08-11T00:00:00+00:00",
    )
    programs = {row.key: row for row in report.by_program}
    assert programs["program"].accepted == 1
    assert programs["other-program"].duplicates == 1
    assert programs["program"].p_accepted.mean > programs["other-program"].p_accepted.mean
    assert programs["program"].payout.expected_payout_usd is None
    assert programs["program"].payout.status == "INSUFFICIENT_EVIDENCE"
    matrix_keys = {row.key for row in report.program_asset_technique_weakness}
    assert "program|web_api|authorization-boundary|authorization" in matrix_keys
    assert "other-program|web_api|authorization-boundary|authorization" in matrix_keys
    repository.close()


def test_payout_requires_five_real_accepted_payouts(tmp_path):
    repository = SQLiteEffectivenessRepository(tmp_path / "ledger.db")
    for index, bounty in enumerate((100, 200, 300, 400, 500), 1):
        item = subject(index)
        repository.record_subject(item, (fact(item, FactType.CANDIDATE_GENERATED),))
        repository.record_outcome(outcome(
            item, bounty=Decimal(bounty), key=f"outcome:{index}",
        ))
    row = calculate_profitability_profiles(
        repository, computed_at="2026-08-11T00:00:00+00:00",
    ).overall
    assert row.payout.expected_payout_usd == Decimal("300")
    assert row.payout.sample_count == 5
    assert row.payout.confidence_class.value == "LOW_CONFIDENCE"
    assert row.payout.model_version == STATISTICAL_MODEL_VERSION
    repository.close()
