from __future__ import annotations

import sqlite3
from dataclasses import replace
from decimal import Decimal

import pytest

from aegis.effectiveness import EffectivenessConflictError, SQLiteEffectivenessRepository
from aegis.effectiveness.economics import project_realized_economics
from aegis.effectiveness.models import (
    CostObservation,
    EconomicsState,
    EffectivenessFact,
    FactType,
    OutcomeInput,
    OutcomeState,
)
from aegis.effectiveness.repository import (
    SQLITE_MIGRATION_CHECKSUM,
    SQLITE_MIGRATION_NAME,
    SQLITE_MIGRATION_VERSION,
    SQLITE_SCHEMA,
)
from aegis.effectiveness.service import LineageValidationError, record_funnel_fact

from .helpers import DIGEST, fact, outcome, subject


def cost(item, *, key="cost:1", rate=Decimal("120"), model=Decimal("2.50")):
    return CostObservation(
        cost_observation_id=f"cost-{key}",
        subject_id=item.subject_id,
        campaign_id=None,
        model_api_cost_usd=model,
        scanner_compute_cost_usd=Decimal("1.25"),
        cloud_cost_usd=Decimal("0"),
        oast_cost_usd=Decimal("0"),
        browser_device_cost_usd=Decimal("0"),
        human_review_minutes=Decimal("30"),
        human_submission_minutes=Decimal("15"),
        human_other_minutes=Decimal("0"),
        human_hourly_rate_usd=rate,
        observed_at="2026-08-11T06:00:00+00:00",
        operator_id="operator",
        source_digest=DIGEST,
        idempotency_key=key,
    )


def test_v2_outcome_and_funnel_vocabularies_are_explicit():
    assert OutcomeState.PENDING.value == "pending"
    assert OutcomeState.WITHDRAWN.value == "withdrawn"
    assert {item.value for item in FactType} >= {
        "opportunity_generated", "candidate_generated", "runtime_observed",
        "locally_reproduced", "independently_verified", "human_approved",
        "submitted", "triaged", "accepted", "paid",
    }


def test_v1_subject_lineage_remains_nullable_and_replayable(tmp_path):
    repository = SQLiteEffectivenessRepository(tmp_path / "ledger.db")
    item = subject()
    assert item.candidate_finding_id is None
    assert item.human_decision_id is None
    assert item.submission_id is None
    assert repository.record_subject(item, (fact(item),))
    assert not repository.record_subject(item, (fact(item),))
    loaded = repository.subject(item.subject_id)
    assert loaded == item
    repository.close()


def test_additive_migration_preserves_raw_v1_subject_and_digest(tmp_path):
    path = tmp_path / "v1.db"
    item = subject()
    legacy_payload = {
        name: getattr(item, name) for name in (
            "subject_id", "run_id", "mission_id", "opportunity_id", "technique",
            "program_id", "asset_id", "weakness_family", "asset_class",
            "authentication_mode", "execution_mode", "evidence_digest", "source_digest",
            "created_at",
        )
    }
    from aegis.effectiveness.models import payload_digest, utc_now

    digest = payload_digest(legacy_payload)
    connection = sqlite3.connect(path)
    connection.executescript(SQLITE_SCHEMA)
    connection.execute(
        "INSERT INTO effectiveness_schema_migrations VALUES (?,?,?,?)",
        (SQLITE_MIGRATION_VERSION, SQLITE_MIGRATION_NAME,
         SQLITE_MIGRATION_CHECKSUM, utc_now()),
    )
    connection.execute(
        "INSERT INTO effectiveness_subjects VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (*legacy_payload.values(), digest),
    )
    legacy_outcome = outcome(item)
    outcome_digest = payload_digest(legacy_outcome)
    connection.execute(
        "INSERT INTO effectiveness_outcome_events VALUES "
        "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "outcome-v1", item.subject_id, 1, legacy_outcome.state.value,
            legacy_outcome.submitted_severity, legacy_outcome.triaged_severity,
            str(legacy_outcome.bounty_usd), legacy_outcome.submitted_at,
            legacy_outcome.triaged_at, legacy_outcome.resolved_at,
            str(legacy_outcome.human_review_minutes),
            str(legacy_outcome.model_api_cost_usd), str(legacy_outcome.compute_cost_usd),
            legacy_outcome.analyst_note, legacy_outcome.operator_id, utc_now(),
            legacy_outcome.source_digest, legacy_outcome.idempotency_key,
            outcome_digest, None,
        ),
    )
    connection.commit()
    connection.close()

    repository = SQLiteEffectivenessRepository(path)
    raw = repository._conn.execute(
        "SELECT payload_digest,candidate_finding_id,human_decision_id,submission_id "
        "FROM effectiveness_subjects WHERE subject_id=?", (item.subject_id,),
    ).fetchone()
    assert tuple(raw) == (digest, None, None, None)
    assert repository.subject(item.subject_id) == item
    assert not repository.record_subject(item)
    assert repository.latest_outcomes()[0].payload == legacy_outcome
    repository.close()


def test_pending_outcome_preserves_unknown_resolution_and_costs(tmp_path):
    repository = SQLiteEffectivenessRepository(tmp_path / "ledger.db")
    item = subject()
    repository.record_subject(item)
    pending = OutcomeInput(
        subject_id=item.subject_id, state=OutcomeState.PENDING,
        submitted_severity="high", triaged_severity=None, bounty_usd=None,
        submitted_at="2026-08-11T06:00:00+00:00", triaged_at=None,
        resolved_at=None, human_review_minutes=None, model_api_cost_usd=None,
        compute_cost_usd=None, analyst_note=None, operator_id="operator",
        source_digest=DIGEST, idempotency_key="pending:1",
    )
    record, inserted = repository.record_outcome(pending)
    assert inserted
    assert record.payload.resolved_at is None
    assert record.payload.human_review_minutes is None
    assert record.payload.model_api_cost_usd is None
    assert record.payload.compute_cost_usd is None
    repository.close()


def test_funnel_fact_append_is_idempotent_and_conflicts_on_mutation(tmp_path):
    repository = SQLiteEffectivenessRepository(tmp_path / "ledger.db")
    item = replace(subject(), candidate_finding_id="candidate-1")
    repository.record_subject(item)
    event = EffectivenessFact(
        fact_id="fact-candidate", subject_id=item.subject_id,
        fact_type=FactType.CANDIDATE_GENERATED,
        observed_at="2026-08-11T06:00:00+00:00", source_digest=DIGEST,
        idempotency_key="fact:candidate", metadata={"candidate_finding_id": "candidate-1"},
        model_version="funnel-v2",
    )
    assert record_funnel_fact(repository, event)
    assert not record_funnel_fact(repository, event)
    with pytest.raises(EffectivenessConflictError, match="different content"):
        repository.record_fact(replace(event, metadata={"candidate_finding_id": "candidate-2"}))
    assert repository.facts() == (event,)
    repository.close()


def test_funnel_stage_requires_and_preserves_evolving_lineage(tmp_path):
    repository = SQLiteEffectivenessRepository(tmp_path / "ledger.db")
    item = subject()
    repository.record_subject(item)
    candidate = EffectivenessFact(
        fact_id="candidate", subject_id=item.subject_id,
        fact_type=FactType.CANDIDATE_GENERATED,
        observed_at="2026-08-11T06:00:00+00:00", source_digest=DIGEST,
        idempotency_key="candidate", metadata={}, model_version="funnel-v2",
    )
    with pytest.raises(LineageValidationError, match="candidate_finding_id"):
        record_funnel_fact(repository, candidate)
    candidate = replace(candidate, metadata={"candidate_finding_id": "candidate-1"})
    assert record_funnel_fact(repository, candidate)
    submission = replace(
        candidate, fact_id="submission", fact_type=FactType.SUBMITTED,
        idempotency_key="submission", metadata={
            "candidate_finding_id": "candidate-1",
            "human_decision_id": "decision-1",
            "submission_id": "submission-1",
        },
    )
    assert record_funnel_fact(repository, submission)
    with pytest.raises(LineageValidationError, match="conflicts"):
        record_funnel_fact(repository, replace(
            submission, fact_id="triage", fact_type=FactType.TRIAGED,
            idempotency_key="triage", metadata={
                **dict(submission.metadata), "candidate_finding_id": "candidate-2",
            },
        ))
    repository.close()


def test_cost_observation_snapshots_human_rate_and_is_immutable(tmp_path):
    repository = SQLiteEffectivenessRepository(tmp_path / "ledger.db")
    item = subject()
    repository.record_subject(item)
    observation = cost(item)
    assert observation.total_human_minutes == Decimal("45")
    assert observation.human_cost_usd == Decimal("90")
    first, inserted = repository.record_cost(observation)
    assert inserted and first.payload == observation
    replay, inserted = repository.record_cost(observation)
    assert not inserted and replay.cost_record_id == first.cost_record_id
    with pytest.raises(EffectivenessConflictError, match="different content"):
        repository.record_cost(replace(observation, model_api_cost_usd=Decimal("3")))
    with pytest.raises(Exception, match="immutable effectiveness ledger"):
        repository._conn.execute(
            "UPDATE effectiveness_cost_observations SET human_hourly_rate_usd='1' "
            "WHERE cost_observation_id=?", (observation.cost_observation_id,),
        )
    repository.close()


def test_unknown_rate_never_turns_human_labor_into_zero():
    item = subject()
    observation = cost(item, rate=None)
    assert observation.total_human_minutes == Decimal("45")
    assert observation.human_cost_usd is None
    projection = project_realized_economics(Decimal("100"), (observation,))
    assert projection.state is EconomicsState.INCOMPLETE
    assert projection.realized_profit_excluding_human_cost_usd == Decimal("96.25")
    assert projection.realized_profit_usd is None
    assert "human_hourly_rate_usd" in projection.missing_inputs


def test_unknown_machine_cost_keeps_both_profit_metrics_unknown():
    item = subject()
    projection = project_realized_economics(
        Decimal("100"), (cost(item, model=None),),
    )
    assert projection.state is EconomicsState.INCOMPLETE
    assert projection.realized_profit_excluding_human_cost_usd is None
    assert projection.realized_profit_usd is None
    assert "model_api_cost_usd" in projection.missing_inputs


def test_complete_costs_produce_both_profit_views():
    projection = project_realized_economics(Decimal("100"), (cost(subject()),))
    assert projection.state is EconomicsState.COMPLETE
    assert projection.machine_infrastructure_cost_usd == Decimal("3.75")
    assert projection.human_cost_usd == Decimal("90")
    assert projection.realized_profit_excluding_human_cost_usd == Decimal("96.25")
    assert projection.realized_profit_usd == Decimal("6.25")
    assert projection.model_version == "realized-economics-v2.0"
