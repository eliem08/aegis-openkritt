"""Compatibility policy gate backed by canonical ``agentic_os.ProposalPolicy``.

Legacy council callers keep their historical dataclasses/reason codes, but authorization is no
longer implemented twice. Scope matching and malformed negative estimates remain compatibility
prechecks; all real action authority is delegated to the canonical proposal policy.
"""

from __future__ import annotations

from ..agentic_os import (
    AgentProposal,
    AuthorizationEnvelope,
    Budget,
    ProposalPolicy,
    mint_execution_grant,
    process_grant_verifier,
)
from .models import ActionProposal, GateDecision, HuntObjective

_REASON_CODES = {
    "forbidden risk class": "high_risk_action_blocked",
    "network access is not authorized": "network_not_authorized",
    "network access requires a verified policy-derived execution grant": "network_not_authorized",
    "external-model egress is not authorized": "model_egress_not_authorized",
    "state changes are not authorized": "state_change_not_authorized",
    "state change requires a verified policy-derived execution grant": "state_change_not_authorized",
    "human approval is required": "human_approval_required",
    "proposal exceeds cost budget": "cost_budget_exceeded",
    "proposal exceeds request budget": "request_budget_exceeded",
    "proposal exceeds human-review budget": "human_budget_exceeded",
}


class PolicyGate:
    """Legacy façade over the canonical fail-closed proposal policy."""

    def __init__(self, policy: ProposalPolicy | None = None) -> None:
        # the legacy façade now goes through the single authority: it derives a signed
        # ExecutionGrant from the operator's HuntObjective and lets the canonical ProposalPolicy
        # verify it — no hand-set network/state-change booleans.
        self._verifier = process_grant_verifier()
        self._policy = policy or ProposalPolicy(self._verifier)

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
        if proposal.requires_human_approval and not human_approved:
            reasons.append("human_approval_required")
        if reasons:
            return GateDecision(allowed=False, reasons=tuple(dict.fromkeys(reasons)))

        remaining_cost = max(0.0, objective.maximum_cost_usd - max(0.0, spent_usd))
        remaining_requests = max(0, objective.maximum_requests - max(0, used_requests))
        budget = Budget(
            max_cost_usd=remaining_cost,
            max_requests=remaining_requests,
            # Legacy objective has no separate human-minute budget. Keep it effectively
            # unbounded here; explicit requires_human_approval is checked above.
            max_human_minutes=1_000_000.0,
        )
        # Derive a SIGNED execution grant from the operator's objective authorization (the single
        # authority), rather than setting capability booleans on the envelope directly.
        grant = mint_execution_grant(
            type("_ObjectiveAuthorization", (), {"allowed": True})(),
            scope_digest=objective.scope_digest, budget=budget, verifier=self._verifier,
            network=objective.network_authorized,
            state_change=objective.state_change_authorized,
            external_model_egress=objective.model_egress_authorized,
            human_approval=human_approved)
        authorization = AuthorizationEnvelope(
            scope_digest=objective.scope_digest,
            external_model_egress_allowed=objective.model_egress_authorized,
            budget=budget,
            grant=grant,
        )
        canonical = AgentProposal(
            role=proposal.agent,
            action=proposal.action,
            rationale=proposal.reason,
            risk=proposal.risk,
            expected_information_gain=max(0.0, proposal.information_gain),
            expected_cost_usd=proposal.estimated_cost_usd,
            expected_requests=proposal.estimated_requests,
            requires_network=proposal.requires_network,
            requires_external_model=proposal.requires_model_egress,
            metadata=proposal.metadata,
        )
        decision = self._policy.evaluate(canonical, authorization)
        if decision.approved:
            return GateDecision(allowed=True)
        code = _REASON_CODES.get(decision.reason, decision.reason.replace(" ", "_"))
        return GateDecision(allowed=False, reasons=(code,))
