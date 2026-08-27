from __future__ import annotations

import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from aegis.effectiveness.funnel import record_funnel_fact
from aegis.effectiveness.models import (
    CampaignEvent,
    EffectivenessFact,
    FactType,
    OutcomeInput,
    OutcomeState,
)
from aegis.effectiveness.policy import EconomicShadowCandidate, build_shadow_policy_batch
from aegis.effectiveness.postgres import PostgresEffectivenessRepository

from .helpers import DIGEST, campaign, cost, fact, outcome, subject

DSN = os.environ.get("AEGIS_TEST_POSTGRES_DSN")


def test_funnel_module_has_no_api_or_fastapi_import_dependency():
    env = dict(os.environ)
    source_root = str(Path(__file__).resolve().parents[2] / "src")
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (source_root, env.get("PYTHONPATH")) if part
    )
    result = subprocess.run(
        [
            sys.executable, "-c",
            "import sys; from aegis.effectiveness.funnel import record_funnel_fact; "
            "assert 'aegis.api' not in sys.modules; assert 'fastapi' not in sys.modules",
        ],
        check=False, capture_output=True, text=True, env=env,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(not DSN, reason="set AEGIS_TEST_POSTGRES_DSN to run")
def test_postgres_concurrent_outcome_is_exactly_once_and_immutable():
    pytest.importorskip("psycopg")
    repository = PostgresEffectivenessRepository(DSN)
    with repository._pool.connection() as connection, connection.cursor() as cursor:
        cursor.execute(
            "TRUNCATE effectiveness_shadow_entries,effectiveness_shadow_batches,"
            "effectiveness_outcome_events,effectiveness_facts,effectiveness_subjects CASCADE"
        )
    item = subject()
    repository.record_subject(item, (fact(item),))
    recorded_outcome = outcome(item)

    def record(_):
        return repository.record_outcome(recorded_outcome)[1]

    with ThreadPoolExecutor(max_workers=8) as pool:
        inserted = list(pool.map(record, range(16)))
    assert inserted.count(True) == 1
    assert inserted.count(False) == 15
    assert len(repository.latest_outcomes()) == 1
    with repository._pool.connection() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="immutable effectiveness ledger"):
            cursor.execute(
                "UPDATE effectiveness_outcome_events SET state='duplicate' "
                "WHERE subject_id=%s", (item.subject_id,),
            )
    repository.close()


@pytest.mark.skipif(not DSN, reason="set AEGIS_TEST_POSTGRES_DSN to run")
def test_postgres_concurrent_cost_is_exactly_once_and_immutable():
    pytest.importorskip("psycopg")
    repository = PostgresEffectivenessRepository(DSN)
    with repository._pool.connection() as connection, connection.cursor() as cursor:
        cursor.execute(
            "TRUNCATE effectiveness_shadow_entries,effectiveness_shadow_batches,"
            "effectiveness_cost_observations,effectiveness_outcome_events,"
            "effectiveness_facts,effectiveness_subjects CASCADE"
        )
    item = subject()
    repository.record_subject(item)
    recorded_cost = cost(item)

    def record(_):
        return repository.record_cost(recorded_cost)[1]

    with ThreadPoolExecutor(max_workers=8) as pool:
        inserted = list(pool.map(record, range(16)))
    assert inserted.count(True) == 1
    assert inserted.count(False) == 15
    assert repository.costs() == (repository.record_cost(recorded_cost)[0],)
    with repository._pool.connection() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="immutable effectiveness ledger"):
            cursor.execute(
                "UPDATE effectiveness_cost_observations SET cloud_cost_usd=1 "
                "WHERE cost_observation_id=%s", (recorded_cost.cost_observation_id,),
            )
    repository.close()


@pytest.mark.skipif(not DSN, reason="set AEGIS_TEST_POSTGRES_DSN to run")
def test_postgres_v2_metadata_and_pending_nulls_round_trip():
    pytest.importorskip("psycopg")
    repository = PostgresEffectivenessRepository(DSN)
    with repository._pool.connection() as connection, connection.cursor() as cursor:
        cursor.execute(
            "TRUNCATE effectiveness_shadow_entries,effectiveness_shadow_batches,"
            "effectiveness_cost_observations,effectiveness_outcome_events,"
            "effectiveness_facts,effectiveness_subjects CASCADE"
        )
    item = subject()
    repository.record_subject(item)
    event = EffectivenessFact(
        fact_id="candidate", subject_id=item.subject_id,
        fact_type=FactType.CANDIDATE_GENERATED, observed_at=datetime.now(UTC).isoformat(),
        source_digest="e" * 64, idempotency_key="candidate",
        metadata={"candidate_finding_id": "candidate-1"}, model_version="funnel-v2",
    )
    assert record_funnel_fact(repository, event)
    assert dict(repository.facts()[0].metadata) == {"candidate_finding_id": "candidate-1"}
    pending_item = subject(2)
    repository.record_subject(pending_item)
    pending = OutcomeInput(
        subject_id=pending_item.subject_id, state=OutcomeState.PENDING,
        submitted_severity="high", triaged_severity=None, bounty_usd=None,
        submitted_at=datetime.now(UTC).isoformat(), triaged_at=None, resolved_at=None,
        human_review_minutes=None, model_api_cost_usd=None, compute_cost_usd=None,
        analyst_note=None, operator_id="operator", source_digest="f" * 64,
        idempotency_key="pending",
    )
    record, inserted = repository.record_outcome(pending)
    assert inserted and record.payload.resolved_at is None
    assert record.payload.model_api_cost_usd is None
    repository.close()


@pytest.mark.skipif(not DSN, reason="set AEGIS_TEST_POSTGRES_DSN to run")
def test_postgres_campaign_jsonb_and_immutable_events_round_trip():
    pytest.importorskip("psycopg")
    repository = PostgresEffectivenessRepository(DSN)
    with repository._pool.connection() as connection, connection.cursor() as cursor:
        cursor.execute(
            "TRUNCATE effectiveness_campaign_events,effectiveness_campaigns CASCADE"
        )
    item = campaign()
    record, inserted = repository.record_campaign(item)
    assert inserted and record.payload == item
    assert repository.record_campaign(item)[1] is False
    event = CampaignEvent(
        campaign_event_id="postgres-event", campaign_id=item.campaign_id,
        event_type="started", observed_at=item.starts_at, subject_id=None,
        metadata={"authority_changed": False}, source_digest=DIGEST,
        idempotency_key="postgres-event",
    )
    assert repository.record_campaign_event(event)
    assert not repository.record_campaign_event(event)
    assert repository.campaign_events(item.campaign_id) == (event,)
    repository.close()


@pytest.mark.skipif(not DSN, reason="set AEGIS_TEST_POSTGRES_DSN to run")
def test_postgres_shadow_economics_round_trip_without_authority():
    pytest.importorskip("psycopg")
    repository = PostgresEffectivenessRepository(DSN)
    with repository._pool.connection() as connection, connection.cursor() as cursor:
        cursor.execute("TRUNCATE effectiveness_shadow_entries,effectiveness_shadow_batches")
    candidates = tuple(
        EconomicShadowCandidate(
            opportunity_id=f"shadow-{index}", program_id="program", asset_class="web_api",
            technique="authorization-boundary", weakness_family="authorization",
            existing_score=Decimal(100 - index), actual_selected=index == 1,
            estimated_hours=Decimal("1"), estimated_requests=10,
            estimated_compute_cost_usd=Decimal("1"),
        )
        for index in range(1, 6)
    )
    batch = build_shadow_policy_batch(
        repository, candidates, batch_id="postgres-shadow", idempotency_key="postgres-shadow",
        selection_count=5, computed_at="2026-08-11T00:00:00+00:00",
    )
    assert repository.record_shadow_batch(batch)
    assert repository.shadow_batches() == (batch,)
    assert all(entry.shadow_hypothetical_reward_usd is None for entry in batch.entries)
    repository.close()
