"""Phase-D cache architecture intelligence over canonical opportunities and missions."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from hashlib import sha256
from typing import Iterable

from aegis.ai.agentic_os import GraphEdge
from aegis.ingest.program import ProgramRules
from aegis.scheduler.profit import HuntOpportunity, allocate

from .cache_intelligence import (
    CacheArchitectureAgent,
    CacheExperiment,
    CacheObservation,
    CacheOutcome,
    CacheVerdict,
)
from .hunter_techniques import HunterTechnique, technique_definition
from .mission_scheduler import MissionPlan
from .universal_mission import compile_opportunity_mission


@dataclass(frozen=True)
class PhaseDResult:
    verdicts: tuple[CacheVerdict, ...]
    opportunities: tuple[HuntOpportunity, ...]
    selected: tuple[HuntOpportunity, ...]
    missions: tuple[MissionPlan, ...]


class HunterIntelligencePhaseD:
    def __init__(self) -> None:
        self.agent = CacheArchitectureAgent()

    def run(
        self, *, program: ProgramRules, scope_digest: str, authorization_id: str,
        asset_locator: str, asset_authorized: bool, graph,
        experiments: Iterable[CacheExperiment] = (),
        deception_pairs: Iterable[tuple[CacheObservation, CacheObservation]] = (),
        backend_available: bool = False, capacity: int = 10,
        exploration_fraction: float = 0.35,
    ) -> PhaseDResult:
        experiment_rows = tuple(experiments)
        deception_rows = tuple(deception_pairs)
        verdicts = tuple(self.agent.evaluate(row) for row in experiment_rows)
        opportunities: list[HuntOpportunity] = []
        for row in verdicts:
            if row.outcome is CacheOutcome.CONSISTENT:
                continue
            technique = (HunterTechnique.CACHE_PRIVATE_SHARED
                         if row.outcome is CacheOutcome.PRIVATE_DATA_SHARED
                         else HunterTechnique.CACHE_KEY_DIFFERENTIAL)
            ready = row.outcome in {
                CacheOutcome.PRIVATE_DATA_SHARED,
                CacheOutcome.SHARED_INFLUENCE_CONFIRMED,
            }
            opportunities.append(self._opportunity(
                program, scope_digest, authorization_id, asset_locator,
                asset_authorized, technique, row.verdict_id, row.confidence,
                row.evidence, "ready" if ready else "complete_cache_controls_required",
                {"oracle_outcome": row.outcome.value, "dimension": row.experiment.dimension,
                 "topology": row.topology, "reason": row.reason},
            ))
        for canonical, variant in deception_rows:
            outcome, reason = self.agent.deception_hypothesis(canonical, variant)
            if outcome is not CacheOutcome.HYPOTHESIS:
                continue
            item_id = "cache-deception:" + sha256(
                f"{canonical.request_id}\x1f{variant.request_id}".encode()
            ).hexdigest()[:20]
            evidence = tuple(dict.fromkeys((*canonical.evidence, *variant.evidence)))
            opportunities.append(self._opportunity(
                program, scope_digest, authorization_id, asset_locator,
                asset_authorized, HunterTechnique.WEB_CACHE_DECEPTION,
                item_id, 0.72, evidence, "ready",
                {"canonical_path": canonical.path, "variant_path": variant.path,
                 "reason": reason},
            ))
        if not experiment_rows and not deception_rows:
            opportunities.append(self._opportunity(
                program, scope_digest, authorization_id, asset_locator,
                asset_authorized, HunterTechnique.CACHE_KEY_DIFFERENTIAL,
                "missing-cache-backend", 0.1, (),
                "cache_observation_backend_required" if not backend_available
                else "controlled_cache_experiment_required", {},
            ))
        rows = tuple(sorted(opportunities, key=lambda item: item.opportunity_id))
        self._persist(graph, asset_locator, asset_authorized, verdicts, rows)
        selected = tuple(item[0] for item in allocate(
            list(rows), capacity=capacity, exploration_fraction=exploration_fraction,
        ))
        missions = tuple(compile_opportunity_mission(item) for item in selected)
        return PhaseDResult(verdicts, rows, selected, missions)

    @staticmethod
    def _opportunity(
        program, scope_digest, authorization_id, asset_locator, asset_authorized,
        technique, hypothesis_id, confidence, evidence, prerequisite, metadata,
    ) -> HuntOpportunity:
        definition = technique_definition(technique)
        if not asset_authorized:
            prerequisite = "scope_confirmation_required"
        opportunity_id = "opp:hunter-d:" + sha256(
            f"{program.handle}\x1f{technique.value}\x1f{hypothesis_id}".encode()
        ).hexdigest()[:20]
        return HuntOpportunity(
            opportunity_id, program_id=program.handle, program_handle=program.handle,
            asset_id="asset:" + sha256(asset_locator.encode()).hexdigest()[:16],
            asset_kind="api", asset_locator=asset_locator, scope_digest=scope_digest,
            authorization_id=authorization_id, attack_surface="cache-architecture",
            weakness_family="cache-boundary", prerequisite_state=prerequisite,
            freshness_score=0.85, estimated_payout_usd=None,
            p_find=max(0.03, confidence * 0.7), p_valid=max(0.03, confidence),
            p_unique=0.78, p_accepted=0.58, p_reproducible=0.9 if evidence else 0.2,
            compute_cost_usd=Decimal("0.002"), validation_cost_usd=Decimal("0.04"),
            information_gain=max(0.1, confidence), uncertainty=max(0.04, 1-confidence),
            provenance=evidence,
            metadata={"technique": technique.value,
                      "worker_capability": definition.worker_capability,
                      "risk_class": definition.risk_class.value,
                      "evidence_requirements": definition.evidence_requirements,
                      "expected_requests": 3, **metadata},
        )

    @staticmethod
    def _persist(graph, asset_locator, authorized, verdicts, opportunities) -> None:
        asset_id = "asset:" + sha256(asset_locator.encode()).hexdigest()[:16]
        graph.upsert_node(asset_id, "api", identifier=asset_locator, authorized=authorized)
        for row in verdicts:
            graph.upsert_node(row.verdict_id, "oracle_result", outcome=row.outcome.value,
                              confidence=row.confidence, topology=row.topology)
            graph.connect(GraphEdge(row.verdict_id, "evaluates", asset_id,
                                    "|".join(row.evidence), row.confidence))
        for row in opportunities:
            graph.upsert_node(row.opportunity_id, "hunt_opportunity",
                              technique=row.metadata.get("technique", ""),
                              prerequisite_state=row.prerequisite_state)
            graph.connect(GraphEdge(row.opportunity_id, "targets", asset_id,
                                    "|".join(row.provenance), row.p_valid))


__all__ = ["HunterIntelligencePhaseD", "PhaseDResult"]
