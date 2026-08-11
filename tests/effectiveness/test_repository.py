from dataclasses import replace

import pytest

from aegis.effectiveness import (
    EffectivenessConflictError,
    EffectivenessStorageStateError,
    SQLiteEffectivenessRepository,
)
from aegis.effectiveness.models import FactType, OutcomeState, confidence_for

from .helpers import fact, outcome, subject


def test_sqlite_is_forbidden_in_production(tmp_path):
    with pytest.raises(EffectivenessStorageStateError, match="forbidden"):
        SQLiteEffectivenessRepository(tmp_path / "ledger.db", production=True)


def test_subject_and_facts_are_transactional_idempotent_and_immutable(tmp_path):
    repository = SQLiteEffectivenessRepository(tmp_path / "ledger.db")
    item = subject()
    facts = (fact(item), fact(item, FactType.FINDING_REPRODUCED))
    assert repository.record_subject(item, facts)
    assert not repository.record_subject(item, facts)
    assert len(repository.subjects()) == 1 and len(repository.facts()) == 2
    with pytest.raises(EffectivenessConflictError):
        repository.record_subject(replace(item, asset_class="mobile"), facts)
    with pytest.raises(Exception, match="immutable effectiveness ledger"):
        repository._conn.execute(
            "UPDATE effectiveness_subjects SET program_id='changed' WHERE subject_id=?",
            (item.subject_id,),
        )
    repository.close()


def test_outcome_is_idempotent_nullable_and_corrected_by_append(tmp_path):
    repository = SQLiteEffectivenessRepository(tmp_path / "ledger.db")
    item = subject()
    repository.record_subject(item, (fact(item),))
    initial = outcome(item, bounty=None)
    first, inserted = repository.record_outcome(initial)
    assert inserted and first.payload.bounty_usd is None and first.version == 1
    replay, inserted = repository.record_outcome(initial)
    assert not inserted and replay.outcome_event_id == first.outcome_event_id
    correction = outcome(
        item, state=OutcomeState.DUPLICATE, bounty=None, key="correction:1",
        supersedes=first.outcome_event_id,
    )
    second, inserted = repository.record_outcome(correction)
    assert inserted and second.version == 2
    assert [record.payload.state for record in repository.outcome_history(item.subject_id)] == [
        OutcomeState.ACCEPTED, OutcomeState.DUPLICATE,
    ]
    assert repository.latest_outcomes()[0].outcome_event_id == second.outcome_event_id
    with pytest.raises(EffectivenessConflictError, match="latest"):
        repository.record_outcome(outcome(
            item, key="correction:stale", supersedes=first.outcome_event_id,
        ))
    repository.close()


@pytest.mark.parametrize("samples,expected", [
    (0, "INSUFFICIENT_DATA"), (4, "INSUFFICIENT_DATA"),
    (5, "LOW_CONFIDENCE"), (14, "LOW_CONFIDENCE"),
    (15, "MODERATE_CONFIDENCE"), (29, "MODERATE_CONFIDENCE"),
    (30, "CALIBRATION_ELIGIBLE"),
])
def test_confidence_boundaries(samples, expected):
    assert confidence_for(samples).value == expected
