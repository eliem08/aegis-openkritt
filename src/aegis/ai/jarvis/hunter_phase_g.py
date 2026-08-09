"""Phase-G cross-surface intelligence on canonical opportunities and missions."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from hashlib import sha256
from typing import Iterable

from aegis.ai.agentic_os import GraphEdge
from aegis.ingest.program import ProgramRules
from aegis.scheduler.profit import HuntOpportunity, allocate

from .cross_surface_intelligence import (
    CrossSurfaceIntelligenceAgent,
    CrossSurfaceKind,
    CrossSurfaceObservation,
    CrossSurfaceOutcome,
    CrossSurfaceVerdict,
)
from .hunter_techniques import HunterTechnique, technique_definition
from .mission_scheduler import MissionPlan
from .universal_mission import compile_opportunity_mission


@dataclass(frozen=True)
class PhaseGResult:
    verdicts: tuple[CrossSurfaceVerdict, ...]
    opportunities: tuple[HuntOpportunity, ...]
    selected: tuple[HuntOpportunity, ...]
    missions: tuple[MissionPlan, ...]


_TECHNIQUES = {
    CrossSurfaceKind.UPLOAD: HunterTechnique.UPLOAD_WORKFLOW_DIFFERENTIAL,
    CrossSurfaceKind.MOBILE_BACKEND: HunterTechnique.MOBILE_BACKEND_CORRELATION,
    CrossSurfaceKind.GRAPHQL: HunterTechnique.GRAPHQL_AUTHORIZATION_DIFFERENTIAL,
    CrossSurfaceKind.WEBSOCKET: HunterTechnique.WEBSOCKET_STATE_DIFFERENTIAL,
    CrossSurfaceKind.GRPC: HunterTechnique.GRPC_AUTHORIZATION_DIFFERENTIAL,
    CrossSurfaceKind.DEEP_LINK: HunterTechnique.DEEP_LINK_TRUST_DIFFERENTIAL,
}


class HunterIntelligencePhaseG:
    def __init__(self) -> None:
        self.agent = CrossSurfaceIntelligenceAgent()

    def run(self, *, program: ProgramRules, scope_digest: str, authorization_id: str,
            asset_locator: str, asset_authorized: bool, graph,
            observations: Iterable[CrossSurfaceObservation] = (),
            backend_available: bool = False, capacity: int = 12,
            exploration_fraction: float = 0.35) -> PhaseGResult:
        observation_rows = tuple(observations)
        verdicts = tuple(self.agent.evaluate(row) for row in observation_rows)
        opportunities = []
        for row in verdicts:
            if row.outcome is CrossSurfaceOutcome.CONSISTENT:
                continue
            ready = row.outcome in {CrossSurfaceOutcome.VIOLATION, CrossSurfaceOutcome.CORRELATION}
            opportunities.append(self._opportunity(
                program, scope_digest, authorization_id, asset_locator,
                asset_authorized, _TECHNIQUES[row.observation.kind], row,
                "ready" if ready else "cross_surface_controls_required",
            ))
        if not observation_rows:
            missing = CrossSurfaceObservation(
                "missing-cross-surface-backend", CrossSurfaceKind.UPLOAD,
                asset_locator, asset_locator, "discover",
                authorized_source=asset_authorized, authorized_target=asset_authorized,
            )
            verdict = CrossSurfaceVerdict(
                "cross-surface:missing", CrossSurfaceOutcome.INCONCLUSIVE,
                "cross-surface backend is not registered", 0.1, missing, (),
            )
            opportunities.append(self._opportunity(
                program, scope_digest, authorization_id, asset_locator, asset_authorized,
                HunterTechnique.UPLOAD_WORKFLOW_DIFFERENTIAL, verdict,
                "cross_surface_backend_required" if not backend_available
                else "synthetic_cross_surface_fixture_required",
            ))
        rows = tuple(sorted(opportunities, key=lambda item: item.opportunity_id))
        self._persist(graph, asset_locator, asset_authorized, verdicts, rows)
        selected = tuple(item[0] for item in allocate(
            list(rows), capacity=capacity, exploration_fraction=exploration_fraction,
        ))
        missions = tuple(compile_opportunity_mission(item) for item in selected)
        return PhaseGResult(verdicts, rows, selected, missions)

    @staticmethod
    def _opportunity(program, scope_digest, authorization_id, asset_locator,
                     asset_authorized, technique, verdict, prerequisite) -> HuntOpportunity:
        definition = technique_definition(technique)
        if not asset_authorized or not verdict.observation.authorized_target:
            prerequisite = "scope_confirmation_required"
        opportunity_id = "opp:hunter-g:" + sha256(
            f"{program.handle}\x1f{technique.value}\x1f{verdict.verdict_id}".encode()
        ).hexdigest()[:20]
        offline = definition.risk_class.value == "offline"
        return HuntOpportunity(
            opportunity_id, program_id=program.handle, program_handle=program.handle,
            asset_id="asset:" + sha256(asset_locator.encode()).hexdigest()[:16],
            asset_kind="api", asset_locator=asset_locator, scope_digest=scope_digest,
            authorization_id=authorization_id, attack_surface=verdict.observation.kind.value,
            weakness_family="cross-surface-authorization", prerequisite_state=prerequisite,
            freshness_score=0.85, estimated_payout_usd=None,
            p_find=max(0.03, verdict.confidence * 0.7), p_valid=max(0.03, verdict.confidence),
            p_unique=0.8, p_accepted=0.6, p_reproducible=0.88 if verdict.evidence else 0.2,
            compute_cost_usd=Decimal("0.003"), validation_cost_usd=Decimal("0.05"),
            information_gain=max(0.1, verdict.confidence),
            uncertainty=max(0.03, 1-verdict.confidence), provenance=verdict.evidence,
            metadata={"technique": technique.value,
                      "worker_capability": definition.worker_capability,
                      "risk_class": definition.risk_class.value,
                      "evidence_requirements": definition.evidence_requirements,
                      "expected_requests": 0 if offline else 3,
                      "oracle_outcome": verdict.outcome.value,
                      "source": verdict.observation.source,
                      "target": verdict.observation.target,
                      "operation": verdict.observation.operation,
                      "reason": verdict.reason},
        )

    @staticmethod
    def _persist(graph, asset_locator, authorized, verdicts, opportunities) -> None:
        asset_id = "asset:" + sha256(asset_locator.encode()).hexdigest()[:16]
        graph.upsert_node(asset_id, "api", identifier=asset_locator, authorized=authorized)
        for row in verdicts:
            graph.upsert_node(row.verdict_id, "oracle_result", outcome=row.outcome.value,
                              surface_kind=row.observation.kind.value,
                              confidence=row.confidence)
            graph.connect(GraphEdge(row.verdict_id, "evaluates", asset_id,
                                    "|".join(row.evidence), row.confidence))
        for row in opportunities:
            graph.upsert_node(row.opportunity_id, "hunt_opportunity",
                              technique=row.metadata.get("technique", ""),
                              prerequisite_state=row.prerequisite_state)
            graph.connect(GraphEdge(row.opportunity_id, "targets", asset_id,
                                    "|".join(row.provenance), row.p_valid))


__all__ = ["HunterIntelligencePhaseG", "PhaseGResult"]
