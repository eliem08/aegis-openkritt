"""Policy gates for Jarvis agent proposals.

Agents never directly widen scope or bypass execution controls. They propose actions,
and this deterministic gate decides whether the orchestrator may schedule them.
"""

from __future__ import annotations

from .models import ActionProposal, GateDecision, HuntObjective, RiskClass


class PolicyGate:
    """Fail-closed authorization gate for agent proposals."""

    def evaluate(
        self,
        objective: HuntObjective,
        proposal: ActionProposal,
        *,
        spent_usd: float = 0.0,
        used_requests: int = 0,
        human_approved: bool = False,
    ) -> GateDecision:
        reasons: list[str] = []

        if proposal.scope_digest != objective.scope_digest:
            reasons.append("scope_digest_mismatch")
        if proposal.estimated_cost_usd < 0:
            reasons.append("negative_cost")
        if proposal.estimated_requests < 0:
            reasons.append("negative_request_count")
        if spent_usd + proposal.estimated_cost_usd > objective.maximum_cost_usd:
            reasons.append("cost_budget_exceeded")
        if used_requests + proposal.estimated_requests > objective.maximum_requests:
            reasons.append("request_budget_exceeded")
        if proposal.requires_network and not objective.network_authorized:
            reasons.append("network_not_authorized")
        if proposal.requires_model_egress and not objective.model_egress_authorized:
            reasons.append("model_egress_not_authorized")
        if proposal.risk is RiskClass.CONTROLLED_STATE_CHANGE:
            if not objective.state_change_authorized:
                reasons.append("state_change_not_authorized")
            if not human_approved:
                reasons.append("human_approval_required")
        if proposal.risk is RiskClass.HIGH_RISK:
            reasons.append("high_risk_action_blocked")
        if proposal.requires_human_approval and not human_approved:
            reasons.append("human_approval_required")

        return GateDecision(allowed=not reasons, reasons=tuple(dict.fromkeys(reasons)))
