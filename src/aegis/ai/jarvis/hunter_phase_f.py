"""Phase-F OAuth and authentication workflow intelligence on canonical missions."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from hashlib import sha256
from typing import Iterable

from aegis.ai.agentic_os import GraphEdge
from aegis.ingest.program import ProgramRules
from aegis.scheduler.profit import HuntOpportunity, allocate

from .hunter_techniques import HunterTechnique, technique_definition
from .mission_scheduler import MissionPlan
from .oauth_intelligence import (
    AuthWorkflowOutcome,
    AuthWorkflowVerdict,
    OAuthFlowObservation,
    OAuthTrustGraphAgent,
    RecoveryObservation,
    SessionInvalidationObservation,
)
from .universal_mission import compile_opportunity_mission


@dataclass(frozen=True)
class PhaseFResult:
    verdicts: tuple[AuthWorkflowVerdict, ...]
    opportunities: tuple[HuntOpportunity, ...]
    selected: tuple[HuntOpportunity, ...]
    missions: tuple[MissionPlan, ...]


class HunterIntelligencePhaseF:
    def __init__(self) -> None:
        self.agent = OAuthTrustGraphAgent()

    def run(
        self, *, program: ProgramRules, scope_digest: str, authorization_id: str,
        asset_locator: str, asset_authorized: bool, graph,
        oauth_flows: Iterable[OAuthFlowObservation] = (),
        recovery_observations: Iterable[RecoveryObservation] = (),
        session_observations: Iterable[SessionInvalidationObservation] = (),
        backend_available: bool = False, capacity: int = 10,
        exploration_fraction: float = 0.35,
    ) -> PhaseFResult:
        flows, recovery, sessions = (tuple(oauth_flows), tuple(recovery_observations),
                                     tuple(session_observations))
        verdicts = tuple(
            item for row in flows for item in self.agent.analyze_flow(row)
        ) + tuple(
            item for row in recovery for item in self.agent.analyze_recovery(row)
        ) + tuple(self.agent.analyze_session(row) for row in sessions)
        opportunities = []
        for row in verdicts:
            if row.outcome is AuthWorkflowOutcome.CONSISTENT:
                continue
            technique = self._technique(row.check)
            opportunities.append(self._opportunity(
                program, scope_digest, authorization_id, asset_locator,
                asset_authorized, technique, row,
                "ready" if row.outcome is AuthWorkflowOutcome.VIOLATION
                else "controlled_auth_workflow_prerequisites_required",
            ))
        if not flows and not recovery and not sessions:
            missing = AuthWorkflowVerdict(
                "auth-workflow:missing", "prerequisites", AuthWorkflowOutcome.INCONCLUSIVE,
                "authentication workflow backend is not registered", 0.1, (),
            )
            opportunities.append(self._opportunity(
                program, scope_digest, authorization_id, asset_locator,
                asset_authorized, HunterTechnique.OAUTH_TRUST_DIFFERENTIAL, missing,
                "auth_workflow_backend_required" if not backend_available
                else "synthetic_auth_account_required",
            ))
        rows = tuple(sorted(opportunities, key=lambda item: item.opportunity_id))
        self._persist(graph, asset_locator, asset_authorized, verdicts, rows)
        selected = tuple(item[0] for item in allocate(
            list(rows), capacity=capacity, exploration_fraction=exploration_fraction,
        ))
        missions = tuple(compile_opportunity_mission(item) for item in selected)
        return PhaseFResult(verdicts, rows, selected, missions)

    @staticmethod
    def _technique(check: str) -> HunterTechnique:
        if check == "postmessage_origin":
            return HunterTechnique.POSTMESSAGE_TRUST_ANALYSIS
        if check == "recovery_token_reuse":
            return HunterTechnique.RECOVERY_STATE_DIFFERENTIAL
        if "session" in check:
            return HunterTechnique.SESSION_INVALIDATION_DIFFERENTIAL
        return HunterTechnique.OAUTH_TRUST_DIFFERENTIAL

    @staticmethod
    def _opportunity(program, scope_digest, authorization_id, asset_locator,
                     asset_authorized, technique, verdict, prerequisite) -> HuntOpportunity:
        definition = technique_definition(technique)
        if not asset_authorized:
            prerequisite = "scope_confirmation_required"
        opportunity_id = "opp:hunter-f:" + sha256(
            f"{program.handle}\x1f{technique.value}\x1f{verdict.verdict_id}".encode()
        ).hexdigest()[:20]
        return HuntOpportunity(
            opportunity_id, program_id=program.handle, program_handle=program.handle,
            asset_id="asset:" + sha256(asset_locator.encode()).hexdigest()[:16],
            asset_kind="api", asset_locator=asset_locator, scope_digest=scope_digest,
            authorization_id=authorization_id, attack_surface="authentication-workflow",
            weakness_family="authentication-trust", prerequisite_state=prerequisite,
            freshness_score=0.88, estimated_payout_usd=None,
            p_find=max(0.03, verdict.confidence * 0.72),
            p_valid=max(0.03, verdict.confidence), p_unique=0.75,
            p_accepted=0.63, p_reproducible=0.9 if verdict.evidence else 0.2,
            compute_cost_usd=Decimal("0.003"), validation_cost_usd=Decimal("0.05"),
            information_gain=max(0.1, verdict.confidence),
            uncertainty=max(0.03, 1-verdict.confidence), provenance=verdict.evidence,
            metadata={"technique": technique.value,
                      "worker_capability": definition.worker_capability,
                      "risk_class": definition.risk_class.value,
                      "evidence_requirements": definition.evidence_requirements,
                      "expected_requests": 3, "oracle_outcome": verdict.outcome.value,
                      "check": verdict.check, "reason": verdict.reason},
        )

    @staticmethod
    def _persist(graph, asset_locator, authorized, verdicts, opportunities) -> None:
        asset_id = "asset:" + sha256(asset_locator.encode()).hexdigest()[:16]
        graph.upsert_node(asset_id, "api", identifier=asset_locator, authorized=authorized)
        for row in verdicts:
            graph.upsert_node(row.verdict_id, "oracle_result", outcome=row.outcome.value,
                              check=row.check, confidence=row.confidence)
            graph.connect(GraphEdge(row.verdict_id, "evaluates", asset_id,
                                    "|".join(row.evidence), row.confidence))
        for row in opportunities:
            graph.upsert_node(row.opportunity_id, "hunt_opportunity",
                              technique=row.metadata.get("technique", ""),
                              prerequisite_state=row.prerequisite_state)
            graph.connect(GraphEdge(row.opportunity_id, "targets", asset_id,
                                    "|".join(row.provenance), row.p_valid))


__all__ = ["HunterIntelligencePhaseF", "PhaseFResult"]
