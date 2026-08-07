"""Specialist agents for Aegis's agentic research operating system."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .agentic_os import (
    AgentContext,
    AgentProposal,
    AgentRole,
    EvidenceRef,
    RiskClass,
)


@dataclass(frozen=True)
class Hypothesis:
    hypothesis_id: str
    description: str
    invariant: str
    affected_components: tuple[str, ...]
    confidence: float
    novelty_score: float
    estimated_severity: float
    duplicate_probability: float
    evidence_needed: tuple[str, ...]
    validation_plan: tuple[str, ...]

    @property
    def research_score(self) -> float:
        confidence = max(0.0, min(1.0, self.confidence))
        novelty = max(0.0, min(1.0, self.novelty_score))
        severity = max(0.0, min(1.0, self.estimated_severity))
        duplicate_discount = 1.0 - max(0.0, min(1.0, self.duplicate_probability))
        return confidence * novelty * severity * duplicate_discount


@dataclass(frozen=True)
class SecurityInvariant:
    invariant_id: str
    subject: str
    predicate: str
    trust_boundary: str
    source_provenance: tuple[str, ...] = ()


class HypothesisAgent:
    role = AgentRole.HYPOTHESIS

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]:
        item = context.memory.get("research:hypotheses")
        if item is None or not isinstance(item.value, list):
            return ()
        proposals: list[AgentProposal] = []
        for hypothesis in item.value:
            if not isinstance(hypothesis, Hypothesis):
                continue
            proposals.append(
                AgentProposal(
                    role=self.role,
                    action="validate_hypothesis",
                    rationale=hypothesis.description,
                    risk=RiskClass.OFFLINE,
                    expected_information_gain=hypothesis.research_score,
                    metadata={
                        "hypothesis_id": hypothesis.hypothesis_id,
                        "invariant": hypothesis.invariant,
                        "validation_plan": hypothesis.validation_plan,
                    },
                )
            )
        return tuple(proposals)


class InvariantAgent:
    role = AgentRole.INVARIANT

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]:
        item = context.memory.get("research:invariants")
        if item is None or not isinstance(item.value, list):
            return ()
        return tuple(
            AgentProposal(
                role=self.role,
                action="falsify_security_invariant",
                rationale=f"Attempt to falsify invariant {inv.invariant_id}: {inv.predicate}",
                risk=RiskClass.OFFLINE,
                expected_information_gain=0.75,
                metadata={
                    "invariant_id": inv.invariant_id,
                    "subject": inv.subject,
                    "trust_boundary": inv.trust_boundary,
                    "source_provenance": inv.source_provenance,
                },
            )
            for inv in item.value
            if isinstance(inv, SecurityInvariant)
        )


class BusinessLogicAgent:
    role = AgentRole.BUSINESS_LOGIC

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]:
        state_nodes = [
            node_id
            for node_id, attrs in context.graph.nodes.items()
            if attrs.get("kind") in {"role", "workflow_state", "entitlement", "tenant"}
        ]
        if not state_nodes:
            return ()
        return (
            AgentProposal(
                role=self.role,
                action="analyze_state_machine_gaps",
                rationale="Search for missing authorization or workflow transitions between known states.",
                risk=RiskClass.OFFLINE,
                expected_information_gain=min(0.95, 0.35 + 0.03 * len(state_nodes)),
                metadata={"state_nodes": tuple(sorted(state_nodes))},
            ),
        )


class AuthorizationAgent:
    role = AgentRole.AUTHORIZATION

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]:
        owner_edges = [edge for edge in context.graph.edges if edge.relation in {"owns", "authorizes"}]
        if not owner_edges:
            return ()
        return (
            AgentProposal(
                role=self.role,
                action="plan_cross_identity_differential",
                rationale="Compare object access across isolated synthetic identities using ownership canaries.",
                risk=RiskClass.READ_ONLY,
                expected_information_gain=0.88,
                expected_requests=6,
                requires_network=True,
                metadata={"relationship_count": len(owner_edges)},
            ),
        )


class HistoryVariantAgent:
    role = AgentRole.VARIANT

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]:
        changes = context.memory.get("history:security_sensitive_changes")
        if changes is None or not changes.value:
            return ()
        return (
            AgentProposal(
                role=self.role,
                action="derive_and_search_variant_queries",
                rationale="Generalize recent security-sensitive changes into structural sibling searches.",
                risk=RiskClass.OFFLINE,
                expected_information_gain=0.82,
                metadata={"change_count": len(changes.value)},
            ),
        )


class ReproductionAgent:
    role = AgentRole.REPRODUCTION

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]:
        proposals: list[AgentProposal] = []
        for finding_id, lifecycle in context.lifecycles.items():
            if lifecycle.stage.value not in {"source_supported", "runtime_observed", "oracle_passed"}:
                continue
            proposals.append(
                AgentProposal(
                    role=self.role,
                    action="run_disposable_local_reproduction",
                    rationale=f"Advance {finding_id} with deterministic local evidence and negative controls.",
                    risk=RiskClass.CONTROLLED_STATE_CHANGE,
                    expected_information_gain=0.94,
                    expected_cost_usd=0.25,
                    expected_human_minutes=2.0,
                    metadata={"finding_id": finding_id, "current_stage": lifecycle.stage.value},
                )
            )
        return tuple(proposals)


class JudgeAgent:
    """Independent adversarial verifier. It never promotes a finding itself."""

    role = AgentRole.JUDGE

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]:
        proposals: list[AgentProposal] = []
        for finding_id, lifecycle in context.lifecycles.items():
            if lifecycle.stage.value not in {"locally_reproduced", "independently_verified"}:
                continue
            evidence = tuple(lifecycle.evidence)
            proposals.append(
                AgentProposal(
                    role=self.role,
                    action="challenge_finding",
                    rationale=(
                        "Try to invalidate reachability, attacker control, authorization assumptions, "
                        "framework behavior, configuration, and claimed impact."
                    ),
                    risk=RiskClass.OFFLINE,
                    expected_information_gain=0.98,
                    evidence=evidence,
                    metadata={"finding_id": finding_id, "mode": "adversarial_verification"},
                )
            )
        return tuple(proposals)


class EvidenceAgent:
    role = AgentRole.EVIDENCE

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]:
        incomplete: list[str] = []
        for finding_id, lifecycle in context.lifecycles.items():
            kinds = {ref.kind for ref in lifecycle.evidence}
            required = {"source_path", "negative_control", "reproduction_oracle"}
            if lifecycle.stage.value in {"locally_reproduced", "independently_verified"} and not required <= kinds:
                incomplete.append(finding_id)
        if not incomplete:
            return ()
        return (
            AgentProposal(
                role=self.role,
                action="complete_evidence_bundle",
                rationale="Submission-quality findings require source path, negative control, and oracle evidence.",
                risk=RiskClass.OFFLINE,
                expected_information_gain=0.9,
                metadata={"finding_ids": tuple(sorted(incomplete))},
            ),
        )


def evidence_ref(kind: str, payload: str, summary: str = "") -> EvidenceRef:
    """Create a deterministic evidence reference without retaining sensitive payload data."""
    from hashlib import sha256

    digest = sha256(payload.encode()).hexdigest()
    return EvidenceRef(evidence_id=f"ev1:{digest}", kind=kind, digest=digest, summary=summary)
