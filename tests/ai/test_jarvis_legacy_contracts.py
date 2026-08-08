from __future__ import annotations

from aegis.ai.agentic_os import AgentRole as CanonicalRole
from aegis.ai.agentic_os import EvidenceStage as CanonicalStage
from aegis.ai.agentic_os import RiskClass as CanonicalRisk
from aegis.ai.jarvis.guards import PolicyGate
from aegis.ai.jarvis.models import (
    ActionProposal,
    AgentRole,
    EvidenceStage,
    HuntObjective,
    RiskClass,
)


def _objective(**overrides):
    values = {
        "program_id": "acme",
        "target": "acme/app",
        "scope_digest": "scope:1",
        "maximum_cost_usd": 10.0,
        "maximum_requests": 5,
    }
    values.update(overrides)
    return HuntObjective(**values)


def _proposal(**overrides):
    values = {
        "agent": AgentRole.SKEPTIC,
        "action": "challenge_hypothesis",
        "reason": "try to falsify the claim",
        "scope_digest": "scope:1",
        "risk": RiskClass.READ_ONLY,
        "estimated_cost_usd": 1.0,
        "estimated_requests": 0,
    }
    values.update(overrides)
    return ActionProposal(**values)


def test_legacy_enums_are_the_canonical_enums():
    assert AgentRole is CanonicalRole
    assert RiskClass is CanonicalRisk
    assert EvidenceStage is CanonicalStage
    assert AgentRole.SKEPTIC is AgentRole.JUDGE
    assert AgentRole.REPORTING is AgentRole.REPORT
    assert RiskClass.HIGH_RISK is RiskClass.FORBIDDEN
    assert EvidenceStage.REPRODUCED is EvidenceStage.LOCALLY_REPRODUCED


def test_legacy_gate_delegates_network_authority_fail_closed():
    decision = PolicyGate().evaluate(
        _objective(network_authorized=False),
        _proposal(requires_network=True),
    )
    assert decision.allowed is False
    assert decision.reasons == ("network_not_authorized",)


def test_legacy_gate_preserves_cumulative_budget_semantics():
    decision = PolicyGate().evaluate(
        _objective(maximum_cost_usd=2.0),
        _proposal(estimated_cost_usd=1.1),
        spent_usd=1.0,
    )
    assert decision.allowed is False
    assert decision.reasons == ("cost_budget_exceeded",)


def test_legacy_high_risk_alias_is_canonically_forbidden():
    decision = PolicyGate().evaluate(
        _objective(),
        _proposal(risk=RiskClass.HIGH_RISK),
    )
    assert decision.allowed is False
    assert decision.reasons == ("high_risk_action_blocked",)
