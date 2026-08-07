from aegis.ai.jarvis.profit_feedback import rank_calibrated_opportunities
from aegis.ai.jarvis.state_store import JarvisStateStore
from aegis.ai.portfolio_agents import Opportunity


def _opportunity(opportunity_id: str, program_id: str) -> Opportunity:
    return Opportunity(
        opportunity_id=opportunity_id,
        program_id=program_id,
        bug_class="authorization",
        expected_payout_usd=2000.0,
        p_valid=0.7,
        p_accepted=0.5,
        p_unique=0.5,
        p_reproducible=0.8,
        compute_cost_usd=5.0,
        review_minutes=20.0,
        information_gain=0.7,
    )


def test_personal_outcomes_change_future_program_ranking(tmp_path) -> None:
    with JarvisStateStore(tmp_path / "feedback.db") as store:
        for _ in range(6):
            store.record_outcome(
                program_id="program-good",
                weakness="authorization",
                accepted=True,
                duplicate=False,
                payout_usd=3000.0,
                cost_usd=20.0,
            )
        for _ in range(6):
            store.record_outcome(
                program_id="program-duplicate-heavy",
                weakness="authorization",
                accepted=False,
                duplicate=True,
                payout_usd=0.0,
                cost_usd=20.0,
            )

        ranked = rank_calibrated_opportunities(
            store,
            (
                _opportunity("good", "program-good"),
                _opportunity("bad", "program-duplicate-heavy"),
            ),
        )
        assert ranked[0].program_id == "program-good"
        assert ranked[0].p_accepted > ranked[1].p_accepted
        assert ranked[0].p_unique > ranked[1].p_unique
