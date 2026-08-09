"""Phase-E race and idempotency intelligence on the canonical mission spine."""

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
from .race_intelligence import RaceConditionAgent, RaceExperiment, RaceOutcome, RaceVerdict
from .universal_mission import compile_opportunity_mission


@dataclass(frozen=True)
class PhaseEResult:
    verdicts: tuple[RaceVerdict, ...]
    opportunities: tuple[HuntOpportunity, ...]
    selected: tuple[HuntOpportunity, ...]
    missions: tuple[MissionPlan, ...]


class HunterIntelligencePhaseE:
    def __init__(self) -> None:
        self.agent = RaceConditionAgent()

    def run(
        self, *, program: ProgramRules, scope_digest: str, authorization_id: str,
        asset_locator: str, asset_authorized: bool, graph,
        experiments: Iterable[RaceExperiment] = (), backend_available: bool = False,
        capacity: int = 10, exploration_fraction: float = 0.35,
    ) -> PhaseEResult:
        experiment_rows = tuple(experiments)
        verdicts = tuple(self.agent.evaluate(row) for row in experiment_rows)
        opportunities = []
        for row in verdicts:
            if row.outcome is RaceOutcome.CONSISTENT:
                continue
            technique = {
                RaceOutcome.IDEMPOTENCY_FAILURE: HunterTechnique.IDEMPOTENCY_KEY_DIFFERENTIAL,
                RaceOutcome.RETRY_DUPLICATED_EFFECT: HunterTechnique.RETRY_STATE_VERIFICATION,
            }.get(row.outcome, HunterTechnique.RACE_SYNCHRONIZED_DIFFERENTIAL)
            ready = row.outcome not in {RaceOutcome.INCONCLUSIVE, RaceOutcome.CONSISTENT}
            opportunities.append(self._opportunity(
                program, scope_digest, authorization_id, asset_locator, asset_authorized,
                technique, row.verdict_id, row.confidence, row.evidence,
                "ready" if ready else "complete_state_readback_required",
                {"oracle_outcome": row.outcome.value, "reason": row.reason,
                 "attempts": len(row.experiment.results)},
            ))
        if not experiment_rows:
            opportunities.append(self._opportunity(
                program, scope_digest, authorization_id, asset_locator, asset_authorized,
                HunterTechnique.RACE_SYNCHRONIZED_DIFFERENTIAL, "missing-race-backend",
                0.1, (), "bounded_race_backend_required" if not backend_available
                else "synthetic_race_fixture_required", {},
            ))
        rows = tuple(sorted(opportunities, key=lambda item: item.opportunity_id))
        self._persist(graph, asset_locator, asset_authorized, verdicts, rows)
        selected = tuple(item[0] for item in allocate(
            list(rows), capacity=capacity, exploration_fraction=exploration_fraction,
        ))
        missions = tuple(compile_opportunity_mission(item) for item in selected)
        return PhaseEResult(verdicts, rows, selected, missions)

    @staticmethod
    def _opportunity(program, scope_digest, authorization_id, asset_locator,
                     asset_authorized, technique, hypothesis_id, confidence, evidence,
                     prerequisite, metadata) -> HuntOpportunity:
        definition = technique_definition(technique)
        if not asset_authorized:
            prerequisite = "scope_confirmation_required"
        opportunity_id = "opp:hunter-e:" + sha256(
            f"{program.handle}\x1f{technique.value}\x1f{hypothesis_id}".encode()
        ).hexdigest()[:20]
        return HuntOpportunity(
            opportunity_id, program_id=program.handle, program_handle=program.handle,
            asset_id="asset:" + sha256(asset_locator.encode()).hexdigest()[:16],
            asset_kind="api", asset_locator=asset_locator, scope_digest=scope_digest,
            authorization_id=authorization_id, attack_surface="race-and-idempotency",
            weakness_family="concurrency-integrity", prerequisite_state=prerequisite,
            freshness_score=0.9, estimated_payout_usd=None,
            p_find=max(0.03, confidence * 0.72), p_valid=max(0.03, confidence),
            p_unique=0.82, p_accepted=0.62, p_reproducible=0.88 if evidence else 0.2,
            compute_cost_usd=Decimal("0.004"), validation_cost_usd=Decimal("0.06"),
            information_gain=max(0.1, confidence), uncertainty=max(0.03, 1-confidence),
            provenance=evidence,
            metadata={"technique": technique.value,
                      "worker_capability": definition.worker_capability,
                      "risk_class": definition.risk_class.value,
                      "evidence_requirements": definition.evidence_requirements,
                      "expected_requests": 4, **metadata},
        )

    @staticmethod
    def _persist(graph, asset_locator, authorized, verdicts, opportunities) -> None:
        asset_id = "asset:" + sha256(asset_locator.encode()).hexdigest()[:16]
        graph.upsert_node(asset_id, "api", identifier=asset_locator, authorized=authorized)
        for row in verdicts:
            graph.upsert_node(row.verdict_id, "oracle_result", outcome=row.outcome.value,
                              confidence=row.confidence, reason=row.reason)
            graph.connect(GraphEdge(row.verdict_id, "evaluates", asset_id,
                                    "|".join(row.evidence), row.confidence))
        for row in opportunities:
            graph.upsert_node(row.opportunity_id, "hunt_opportunity",
                              technique=row.metadata.get("technique", ""),
                              prerequisite_state=row.prerequisite_state)
            graph.connect(GraphEdge(row.opportunity_id, "targets", asset_id,
                                    "|".join(row.provenance), row.p_valid))


__all__ = ["HunterIntelligencePhaseE", "PhaseEResult"]
