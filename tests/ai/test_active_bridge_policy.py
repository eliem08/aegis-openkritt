from __future__ import annotations

from aegis.ai.active_bridge import proposals_from_plan
from aegis.ai.agentic_os import AuthorizationEnvelope, Budget, ProposalPolicy
from aegis.active.detectors import DetectorPlan, DetectorTask


def test_live_active_task_is_blocked_by_default_source_review_policy():
    plan = DetectorPlan(
        tasks=[
            DetectorTask(
                detector="ssrf",
                action="benign_request_mutation",
                targets=("/webhook",),
                config={"parameters": ["url"]},
                est_requests=2,
            )
        ]
    )
    proposal = proposals_from_plan(plan)[0]
    assert proposal.metadata["execution"] == "proposal_only"
    assert proposal.requires_network is True

    decision = ProposalPolicy().evaluate(
        proposal,
        AuthorizationEnvelope(scope_digest="scope", budget=Budget(max_requests=10)),
    )
    assert decision.approved is False
    assert "network" in decision.reason
