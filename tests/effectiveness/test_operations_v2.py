from dataclasses import replace

import pytest

from aegis.effectiveness.models import (
    CampaignEvent,
    EffectivenessFact,
    FactType,
)
from aegis.effectiveness.operations import daily_profitability_document, pending_review_queue
from aegis.effectiveness.repository import EffectivenessConflictError, SQLiteEffectivenessRepository

from .helpers import DIGEST, campaign, subject


def test_campaign_and_events_are_append_only_and_idempotent(tmp_path):
    repository = SQLiteEffectivenessRepository(tmp_path / "ledger.db")
    item = campaign()
    record, inserted = repository.record_campaign(item)
    assert inserted and record.payload == item
    assert repository.record_campaign(item)[1] is False
    with pytest.raises(EffectivenessConflictError):
        repository.record_campaign(replace(item, time_budget_minutes="61"))
    event = CampaignEvent(
        campaign_event_id="event-1", campaign_id=item.campaign_id, event_type="started",
        observed_at=item.starts_at, subject_id=None, metadata={"authority_changed": False},
        source_digest=DIGEST, idempotency_key="event:1",
    )
    assert repository.record_campaign_event(event)
    assert not repository.record_campaign_event(event)
    assert repository.campaign_events(item.campaign_id) == (event,)
    with pytest.raises(Exception, match="immutable effectiveness ledger"):
        repository._conn.execute("DELETE FROM effectiveness_campaigns")
    repository.close()


def test_review_queue_and_daily_report_never_claim_authority(tmp_path):
    repository = SQLiteEffectivenessRepository(tmp_path / "ledger.db")
    item = subject()
    candidate = EffectivenessFact(
        fact_id="candidate", subject_id=item.subject_id,
        fact_type=FactType.CANDIDATE_GENERATED,
        observed_at="2026-08-11T00:00:00+00:00", source_digest=DIGEST,
        idempotency_key="candidate", metadata={}, model_version="funnel-v2",
    )
    fact = EffectivenessFact(
        fact_id="verified", subject_id=item.subject_id,
        fact_type=FactType.INDEPENDENTLY_VERIFIED,
        observed_at="2026-08-11T00:00:00+00:00", source_digest=DIGEST,
        idempotency_key="verified", metadata={"title": "finding"}, model_version="funnel-v2",
    )
    repository.record_subject(item, (candidate, fact))
    queue = pending_review_queue(repository)
    assert queue[0]["reason"] == "HUMAN_REVIEW_REQUIRED"
    assert queue[0]["report_quality"] == "INCOMPLETE"
    report = daily_profitability_document(
        repository, computed_at="2026-08-11T02:00:00+00:00",
    )
    assert report["production_authority_changed"] is False
    assert report["human_submission_mandatory"] is True
    assert report["economics"]["realized_profit_usd"] is None
    repository.close()
