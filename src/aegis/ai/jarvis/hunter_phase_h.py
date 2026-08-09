"""Phase-H exploit-chain and coverage/economic intelligence on canonical missions."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from hashlib import sha256
from typing import Iterable

from aegis.ai.agentic_os import GraphEdge
from aegis.ingest.program import ProgramRules
from aegis.scheduler.profit import HuntOpportunity, allocate

from .exploit_chain_intelligence import (
    CapabilityChain,
    CoverageStateCell,
    EvidenceCapability,
    ExploitChainAgentV2,
    TechniqueEconomicModel,
    TechniqueOutcome,
    TechniquePrior,
    select_state_cells,
)
from .hunter_techniques import HunterTechnique, technique_definition
from .mission_scheduler import MissionPlan
from .universal_mission import compile_opportunity_mission


@dataclass(frozen=True)
class PhaseHResult:
    chains: tuple[CapabilityChain, ...]
    priors: tuple[TechniquePrior, ...]
    selected_state_cells: tuple[CoverageStateCell, ...]
    opportunities: tuple[HuntOpportunity, ...]
    selected: tuple[HuntOpportunity, ...]
    missions: tuple[MissionPlan, ...]


class HunterIntelligencePhaseH:
    def __init__(self) -> None:
        self.chain_agent = ExploitChainAgentV2()
        self.economic_model = TechniqueEconomicModel()

    def run(self, *, program: ProgramRules, scope_digest: str, authorization_id: str,
            asset_locator: str, asset_authorized: bool, graph,
            capabilities: Iterable[EvidenceCapability] = (),
            initial_capabilities: Iterable[str] = (),
            technique_outcomes: Iterable[TechniqueOutcome] = (),
            state_cells: Iterable[CoverageStateCell] = (), state_cell_limit: int = 4,
            capacity: int = 12, exploration_fraction: float = 0.35) -> PhaseHResult:
        chains = self.chain_agent.build(
            capabilities, initial_capabilities=initial_capabilities
        )
        priors = self.economic_model.learn(technique_outcomes)
        cells = select_state_cells(state_cells, limit=state_cell_limit)
        opportunities = [self._chain_opportunity(
            program, scope_digest, authorization_id, asset_locator,
            asset_authorized, chain,
        ) for chain in chains]
        opportunities.extend(self._cell_opportunity(
            program, scope_digest, authorization_id, asset_locator,
            asset_authorized, cell,
        ) for cell in cells)
        prior_map = {row.technique: row for row in priors}
        opportunities = [
            self.economic_model.calibrate(row, prior_map[str(row.metadata.get("technique", ""))])
            if str(row.metadata.get("technique", "")) in prior_map else row
            for row in opportunities
        ]
        rows = tuple(sorted(opportunities, key=lambda item: item.opportunity_id))
        self._persist(graph, asset_locator, asset_authorized, chains, priors, cells, rows)
        selected = tuple(item[0] for item in allocate(
            list(rows), capacity=capacity, exploration_fraction=exploration_fraction,
        ))
        missions = tuple(compile_opportunity_mission(item) for item in selected)
        return PhaseHResult(chains, priors, cells, rows, selected, missions)

    @staticmethod
    def _base(program, scope_digest, authorization_id, asset_locator, asset_authorized,
              technique, item_id, confidence, evidence, prerequisite, payout, metadata):
        definition = technique_definition(technique)
        if not asset_authorized:
            prerequisite = "scope_confirmation_required"
        opportunity_id = "opp:hunter-h:" + sha256(
            f"{program.handle}\x1f{technique.value}\x1f{item_id}".encode()
        ).hexdigest()[:20]
        return HuntOpportunity(
            opportunity_id, program_id=program.handle, program_handle=program.handle,
            asset_id="asset:" + sha256(asset_locator.encode()).hexdigest()[:16],
            asset_kind="api", asset_locator=asset_locator, scope_digest=scope_digest,
            authorization_id=authorization_id, attack_surface="exploit-chain",
            weakness_family="multi-step-impact", prerequisite_state=prerequisite,
            freshness_score=0.82, coverage_score=metadata.get("coverage_score", 0.0),
            estimated_payout_usd=payout, p_find=max(0.03, confidence * 0.7),
            p_valid=max(0.03, confidence), p_unique=0.82, p_accepted=0.6,
            p_reproducible=0.85 if evidence else 0.2,
            compute_cost_usd=Decimal("0.003"), validation_cost_usd=Decimal("0.04"),
            information_gain=max(0.1, confidence), uncertainty=max(0.03, 1-confidence),
            provenance=evidence,
            metadata={"technique": technique.value,
                      "worker_capability": definition.worker_capability,
                      "risk_class": definition.risk_class.value,
                      "evidence_requirements": definition.evidence_requirements,
                      "expected_requests": (3 if definition.risk_class.value
                                              == "controlled_state_change" else 0),
                      **metadata},
        )

    @classmethod
    def _chain_opportunity(cls, program, scope_digest, authorization_id, asset_locator,
                           asset_authorized, chain):
        return cls._base(
            program, scope_digest, authorization_id, asset_locator, asset_authorized,
            HunterTechnique.EXPLOIT_CAPABILITY_CHAIN, chain.chain_id, chain.confidence,
            chain.evidence, chain.prerequisite_state, chain.expected_payout_usd,
            {"chain_id": chain.chain_id,
             "steps": tuple(item.capability_id for item in chain.steps),
             "final_capabilities": chain.final_capabilities,
             "chain_expected_net_usd": (None if chain.expected_net_usd is None
                                        else float(chain.expected_net_usd))},
        )

    @classmethod
    def _cell_opportunity(cls, program, scope_digest, authorization_id, asset_locator,
                          asset_authorized, cell):
        information = min(1.0, 1 / (cell.attempts + 1) + (0.3 if cell.changed else 0))
        return cls._base(
            program, scope_digest, authorization_id, asset_locator, asset_authorized,
            HunterTechnique.COVERAGE_STATE_FUZZING, cell.cell_id, information, (),
            cell.prerequisite_state, None,
            {"cell_id": cell.cell_id, "state": cell.state, "operation": cell.operation,
             "identity_class": cell.identity_class, "prior_attempts": cell.attempts,
             "coverage_score": information},
        )

    @staticmethod
    def _persist(graph, asset_locator, authorized, chains, priors, cells, opportunities):
        asset_id = "asset:" + sha256(asset_locator.encode()).hexdigest()[:16]
        graph.upsert_node(asset_id, "api", identifier=asset_locator, authorized=authorized)
        for row in chains:
            graph.upsert_node(row.chain_id, "capability_chain", confidence=row.confidence,
                              steps=tuple(item.capability_id for item in row.steps))
            graph.connect(GraphEdge(row.chain_id, "evaluates", asset_id,
                                    "|".join(row.evidence), row.confidence))
        for row in priors:
            graph.upsert_node(f"technique-prior:{row.technique}", "technique_prior",
                              samples=row.samples, applicable_samples=row.applicable_samples,
                              acceptance_probability=row.acceptance_probability,
                              uniqueness_probability=row.uniqueness_probability)
        for row in cells:
            graph.upsert_node(row.cell_id, "coverage_state", state=row.state,
                              operation=row.operation, attempts=row.attempts)
        for row in opportunities:
            graph.upsert_node(row.opportunity_id, "hunt_opportunity",
                              technique=row.metadata.get("technique", ""),
                              prerequisite_state=row.prerequisite_state)
            graph.connect(GraphEdge(row.opportunity_id, "targets", asset_id,
                                    "|".join(row.provenance), row.p_valid))


__all__ = ["HunterIntelligencePhaseH", "PhaseHResult"]
