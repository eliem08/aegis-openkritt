"""Phase-B identity and business-logic intelligence on the canonical hunt spine."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from hashlib import sha256
from typing import Iterable

from aegis.ai.agentic_os import GraphEdge
from aegis.ingest.program import ProgramRules
from aegis.scheduler.profit import HuntOpportunity, allocate

from .hunter_techniques import HunterTechnique, technique_definition
from .identity_intelligence import (
    AccessObservation,
    AuthorizationMatrix,
    DifferentialOutcome,
    DifferentialVerdict,
    ErrorStateVerifier,
    IdentityDifferentialOracle,
    LifecycleHypothesis,
    LifecycleStateAgent,
    LifecycleTransitionRule,
    StateVerification,
    StateVerificationOutcome,
)
from .mission_scheduler import MissionPlan
from .universal_mission import compile_opportunity_mission


@dataclass(frozen=True)
class PhaseBResult:
    authorization_verdicts: tuple[DifferentialVerdict, ...]
    lifecycle_hypotheses: tuple[LifecycleHypothesis, ...]
    state_verifications: tuple[StateVerification, ...]
    opportunities: tuple[HuntOpportunity, ...]
    selected: tuple[HuntOpportunity, ...]
    missions: tuple[MissionPlan, ...]


def _opportunity(
    *, program: ProgramRules, scope_digest: str, authorization_id: str,
    asset_locator: str, asset_authorized: bool, technique: HunterTechnique,
    confidence: float, evidence: tuple[str, ...], hypothesis_id: str,
    prerequisite: str = "ready", metadata: dict[str, object] | None = None,
) -> HuntOpportunity:
    definition = technique_definition(technique)
    effective_prerequisite = prerequisite if asset_authorized else "scope_confirmation_required"
    opportunity_id = "opp:hunter-b:" + sha256(
        f"{program.handle}\x1f{asset_locator}\x1f{technique.value}\x1f{hypothesis_id}".encode()
    ).hexdigest()[:20]
    return HuntOpportunity(
        opportunity_id,
        program_id=program.handle,
        program_handle=program.handle,
        asset_id="asset:" + sha256(asset_locator.encode()).hexdigest()[:16],
        asset_kind="api",
        asset_locator=asset_locator,
        scope_digest=scope_digest,
        authorization_id=authorization_id,
        attack_surface=technique.value,
        weakness_family=("business-logic-state" if technique is
                         HunterTechnique.BUSINESS_STATE_COMBINATION else
                         "authorization-boundary"),
        prerequisite_state=effective_prerequisite,
        freshness_score=0.85,
        estimated_payout_usd=None,
        p_find=max(0.03, min(0.9, confidence * 0.7)),
        p_valid=max(0.03, min(0.98, confidence)),
        p_unique=0.72,
        p_accepted=0.58,
        p_reproducible=0.9 if evidence else 0.2,
        compute_cost_usd=Decimal("0.003"),
        validation_cost_usd=Decimal("0.05"),
        information_gain=max(0.1, confidence),
        uncertainty=max(0.05, 1.0 - confidence),
        provenance=evidence,
        metadata={
            "technique": technique.value,
            "worker_capability": definition.worker_capability,
            "risk_class": definition.risk_class.value,
            "evidence_requirements": definition.evidence_requirements,
            "expected_requests": 2,
            "hypothesis_id": hypothesis_id,
            **(metadata or {}),
        },
    )


class HunterIntelligencePhaseB:
    """Observations -> oracles -> opportunities -> economic selection -> missions."""

    def __init__(self) -> None:
        self.identity_oracle = IdentityDifferentialOracle()
        self.lifecycle_agent = LifecycleStateAgent()
        self.error_verifier = ErrorStateVerifier()

    def run(
        self,
        *,
        program: ProgramRules,
        scope_digest: str,
        authorization_id: str,
        asset_locator: str,
        asset_authorized: bool,
        graph,
        identity_pairs: Iterable[tuple[AccessObservation, AccessObservation]] = (),
        authorization_matrix: AuthorizationMatrix | None = None,
        state_observations: Iterable[tuple[AccessObservation, tuple[str, ...]]] = (),
        lifecycle_rules: Iterable[LifecycleTransitionRule] = (),
        observed_states: Iterable[str] = (),
        capacity: int = 10,
        exploration_fraction: float = 0.35,
    ) -> PhaseBResult:
        matrix = authorization_matrix or AuthorizationMatrix()
        pairs = tuple(identity_pairs)
        verdicts = tuple(
            self.identity_oracle.evaluate(control, probe, matrix)
            for control, probe in pairs
        )
        state_verifications = tuple(
            self.error_verifier.verify(observation, expected_effects=effects)
            for observation, effects in state_observations
        )
        lifecycle = self.lifecycle_agent.hypotheses(
            lifecycle_rules, observed_states=observed_states
        )
        opportunities = self._opportunities(
            program=program, scope_digest=scope_digest,
            authorization_id=authorization_id, asset_locator=asset_locator,
            asset_authorized=asset_authorized, verdicts=verdicts,
            state_verifications=state_verifications, lifecycle=lifecycle,
            has_pairs=bool(pairs),
        )
        self._persist(graph, asset_locator, asset_authorized, verdicts,
                      state_verifications, lifecycle, opportunities)
        selected_rows = allocate(
            list(opportunities), capacity=capacity,
            exploration_fraction=exploration_fraction,
        )
        selected = tuple(row[0] for row in selected_rows)
        missions = tuple(compile_opportunity_mission(item) for item in selected)
        return PhaseBResult(
            verdicts, lifecycle, state_verifications, opportunities, selected, missions
        )

    @staticmethod
    def _opportunities(
        *, program: ProgramRules, scope_digest: str, authorization_id: str,
        asset_locator: str, asset_authorized: bool,
        verdicts: tuple[DifferentialVerdict, ...],
        state_verifications: tuple[StateVerification, ...],
        lifecycle: tuple[LifecycleHypothesis, ...], has_pairs: bool,
    ) -> tuple[HuntOpportunity, ...]:
        rows: list[HuntOpportunity] = []
        if not has_pairs:
            rows.append(_opportunity(
                program=program, scope_digest=scope_digest,
                authorization_id=authorization_id, asset_locator=asset_locator,
                asset_authorized=asset_authorized,
                technique=HunterTechnique.AUTH_OBJECT_DIFFERENTIAL,
                confidence=0.1, evidence=(), hypothesis_id="missing-controlled-pair",
                prerequisite="controlled_identity_pair_required",
            ))
        techniques = {
            "account": HunterTechnique.AUTH_OBJECT_DIFFERENTIAL,
            "role": HunterTechnique.AUTH_ROLE_DIFFERENTIAL,
            "tenant": HunterTechnique.AUTH_TENANT_DIFFERENTIAL,
        }
        for item in verdicts:
            if item.outcome is DifferentialOutcome.CONSISTENT:
                continue
            prerequisite = (
                "ready" if item.outcome is DifferentialOutcome.VIOLATION
                else "explicit_policy_or_control_evidence_required"
            )
            rows.append(_opportunity(
                program=program, scope_digest=scope_digest,
                authorization_id=authorization_id, asset_locator=asset_locator,
                asset_authorized=asset_authorized, technique=techniques[item.dimension],
                confidence=item.confidence, evidence=item.evidence,
                hypothesis_id=item.verdict_id, prerequisite=prerequisite,
                metadata={"oracle_outcome": item.outcome.value, "reason": item.reason},
            ))
        for item in state_verifications:
            if item.outcome in {
                StateVerificationOutcome.CLEAN_ROLLBACK,
                StateVerificationOutcome.COMPLETE_COMMIT,
            }:
                continue
            technique = (
                HunterTechnique.PARTIAL_COMMIT_VERIFICATION
                if item.outcome is StateVerificationOutcome.PARTIAL_COMMIT
                else HunterTechnique.POST_ERROR_STATE_CHECK
            )
            prerequisite = (
                "ready" if item.outcome in {
                    StateVerificationOutcome.PARTIAL_COMMIT,
                    StateVerificationOutcome.HIDDEN_COMMIT,
                } else "state_readback_required"
            )
            rows.append(_opportunity(
                program=program, scope_digest=scope_digest,
                authorization_id=authorization_id, asset_locator=asset_locator,
                asset_authorized=asset_authorized, technique=technique,
                confidence=item.confidence, evidence=item.evidence,
                hypothesis_id=item.verification_id, prerequisite=prerequisite,
                metadata={"state_outcome": item.outcome.value, "reason": item.reason},
            ))
        for item in lifecycle:
            hypothesis_id = "lifecycle:" + sha256(
                f"{item.operation}\x1f{item.from_state}\x1f{item.to_state}".encode()
            ).hexdigest()[:16]
            rows.append(_opportunity(
                program=program, scope_digest=scope_digest,
                authorization_id=authorization_id, asset_locator=asset_locator,
                asset_authorized=asset_authorized,
                technique=HunterTechnique.BUSINESS_STATE_COMBINATION,
                confidence=item.confidence, evidence=item.evidence,
                hypothesis_id=hypothesis_id,
                metadata={"operation": item.operation, "from_state": item.from_state,
                          "to_state": item.to_state},
            ))
        return tuple(sorted(
            {item.opportunity_id: item for item in rows}.values(),
            key=lambda item: item.opportunity_id,
        ))

    @staticmethod
    def _persist(graph, asset_locator: str, asset_authorized: bool,
                 verdicts, state_verifications, lifecycle, opportunities) -> None:
        asset_id = "asset:" + sha256(asset_locator.encode()).hexdigest()[:16]
        graph.upsert_node(asset_id, "api", identifier=asset_locator,
                          authorized=asset_authorized, inferred=False)
        for item in (*verdicts, *state_verifications):
            item_id = getattr(item, "verdict_id", getattr(item, "verification_id", ""))
            outcome = item.outcome.value
            graph.upsert_node(item_id, "oracle_result", outcome=outcome,
                              confidence=item.confidence, reason=item.reason)
            graph.connect(GraphEdge(item_id, "evaluates", asset_id,
                                    "|".join(item.evidence), item.confidence))
        for item in lifecycle:
            item_id = "lifecycle:" + sha256(
                f"{item.operation}\x1f{item.from_state}\x1f{item.to_state}".encode()
            ).hexdigest()[:16]
            graph.upsert_node(item_id, "lifecycle_hypothesis", operation=item.operation,
                              from_state=item.from_state, to_state=item.to_state,
                              confidence=item.confidence)
            graph.connect(GraphEdge(item_id, "evaluates", asset_id,
                                    "|".join(item.evidence), item.confidence))
        for item in opportunities:
            graph.upsert_node(item.opportunity_id, "hunt_opportunity",
                              technique=item.metadata.get("technique", ""),
                              prerequisite_state=item.prerequisite_state)
            graph.connect(GraphEdge(item.opportunity_id, "targets", asset_id,
                                    "|".join(item.provenance), item.p_valid))


__all__ = ["HunterIntelligencePhaseB", "PhaseBResult"]
