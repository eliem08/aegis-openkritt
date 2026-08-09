from __future__ import annotations

from aegis.ai.jarvis.state_store import (
    BountyResolution,
    JarvisStateStore,
    RealBountyOutcome,
)


def test_real_outcomes_are_idempotent_nullable_and_technique_specific(tmp_path):
    path = tmp_path / "jarvis.db"
    accepted = RealBountyOutcome(
        outcome_id="h1:100",
        program_id="example",
        technique="graphql_auth_differential",
        weakness="authorization",
        resolution=BountyResolution.ACCEPTED,
        severity="high",
        bounty_usd=0.0,
        time_to_triage_seconds=7200,
        cost_usd=1.25,
        source="hackerone-report:100",
        resolved_at="2026-08-09T20:00:00+00:00",
    )
    unknown_bounty = RealBountyOutcome(
        outcome_id="h1:101",
        program_id="example",
        technique="graphql_auth_differential",
        weakness="authorization",
        resolution=BountyResolution.DUPLICATE,
        severity=None,
        bounty_usd=None,
        time_to_triage_seconds=None,
        cost_usd=0.5,
        source="hackerone-report:101",
        resolved_at="2026-08-09T21:00:00+00:00",
    )
    with JarvisStateStore(path) as store:
        first = store.record_real_outcome(accepted)
        repeated = store.record_real_outcome(accepted)
        duplicate = store.record_real_outcome(unknown_bounty)
        rows = store.real_outcomes(technique="graphql_auth_differential")
        weakness = store.learned_prior("example", "authorization")
        technique = store.learned_prior(
            "example", "technique:graphql_auth_differential"
        )
    assert first.recorded and not repeated.recorded and duplicate.recorded
    assert len(rows) == 2
    assert rows[0].bounty_usd == 0.0
    assert rows[1].bounty_usd is None
    assert weakness.samples == 2 and technique.samples == 2
    assert weakness.mean_payout_usd is None
    assert weakness.acceptance_probability == technique.acceptance_probability


def test_informative_outcome_is_durable_but_does_not_train_acceptance(tmp_path):
    with JarvisStateStore(tmp_path / "jarvis.db") as store:
        learning = store.record_real_outcome(RealBountyOutcome(
            outcome_id="h1:informative",
            program_id="example",
            technique="cache_key_differential",
            weakness="cache",
            resolution=BountyResolution.INFORMATIVE,
            bounty_usd=None,
            cost_usd=0.1,
            source="hackerone-report:informative",
            resolved_at="2026-08-09T22:00:00+00:00",
        ))
        rows = store.real_outcomes()
    assert learning.recorded
    assert learning.technique_prior.samples == 0
    assert rows[0].resolution is BountyResolution.INFORMATIVE
