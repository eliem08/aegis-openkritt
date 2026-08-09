"""Phase-C server-side URL consumer intelligence over canonical opportunities/missions."""

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
from .universal_mission import compile_opportunity_mission
from .url_consumer_intelligence import (
    ServerSideURLConsumerAgent,
    URLConsumerOutcome,
    URLConsumerProbe,
    URLConsumerSurface,
    URLConsumerVerdict,
)


@dataclass(frozen=True)
class PhaseCResult:
    surfaces: tuple[URLConsumerSurface, ...]
    verdicts: tuple[URLConsumerVerdict, ...]
    opportunities: tuple[HuntOpportunity, ...]
    selected: tuple[HuntOpportunity, ...]
    missions: tuple[MissionPlan, ...]


def _opportunity(
    *, program: ProgramRules, scope_digest: str, authorization_id: str,
    asset_locator: str, surface: URLConsumerSurface, technique: HunterTechnique,
    prerequisite: str, confidence: float, evidence: tuple[str, ...],
    hypothesis_id: str, metadata: dict[str, object] | None = None,
) -> HuntOpportunity:
    definition = technique_definition(technique)
    if not surface.authorized:
        prerequisite = "scope_confirmation_required"
    opportunity_id = "opp:hunter-c:" + sha256(
        f"{program.handle}\x1f{surface.surface_id}\x1f{technique.value}\x1f{hypothesis_id}".encode()
    ).hexdigest()[:20]
    return HuntOpportunity(
        opportunity_id, program_id=program.handle, program_handle=program.handle,
        asset_id="asset:" + sha256(asset_locator.encode()).hexdigest()[:16],
        asset_kind="api", asset_locator=asset_locator, scope_digest=scope_digest,
        authorization_id=authorization_id, attack_surface=surface.kind.value,
        weakness_family="server-side-url-consumption", prerequisite_state=prerequisite,
        freshness_score=0.9, estimated_payout_usd=None,
        p_find=max(0.03, min(0.92, confidence * 0.75)),
        p_valid=max(0.03, min(0.99, confidence)), p_unique=0.7,
        p_accepted=0.62, p_reproducible=0.92 if evidence else 0.2,
        compute_cost_usd=Decimal("0.002"), validation_cost_usd=Decimal("0.03"),
        information_gain=max(0.1, confidence), uncertainty=max(0.03, 1.0 - confidence),
        provenance=evidence,
        metadata={
            "technique": technique.value, "worker_capability": definition.worker_capability,
            "risk_class": definition.risk_class.value,
            "evidence_requirements": definition.evidence_requirements,
            "expected_requests": 1, "surface_id": surface.surface_id,
            "route": surface.route, "parameter": surface.parameter,
            "delivery": surface.delivery.value, **(metadata or {}),
        },
    )


class HunterIntelligencePhaseC:
    def __init__(self) -> None:
        self.agent = ServerSideURLConsumerAgent()

    def run(
        self, *, program: ProgramRules, scope_digest: str, authorization_id: str,
        asset_locator: str, graph, surfaces: Iterable[URLConsumerSurface] = (),
        probes: Iterable[URLConsumerProbe] = (), private_oast_available: bool = False,
        capacity: int = 10, exploration_fraction: float = 0.35,
    ) -> PhaseCResult:
        surface_rows = tuple(surfaces)
        probe_rows = tuple(probes)
        known = {row.surface_id: row for row in surface_rows}
        known.update((row.surface.surface_id, row.surface) for row in probe_rows)
        surface_rows = tuple(sorted(known.values(), key=lambda row: row.surface_id))
        verdicts = tuple(self.agent.analyze(row) for row in probe_rows)
        by_surface = {row.probe.surface.surface_id: row for row in verdicts}
        opportunities = []
        for surface in surface_rows:
            verdict = by_surface.get(surface.surface_id)
            if verdict is None:
                opportunities.append(_opportunity(
                    program=program, scope_digest=scope_digest,
                    authorization_id=authorization_id, asset_locator=asset_locator,
                    surface=surface, technique=HunterTechnique.SSRF_URL_CONSUMER,
                    prerequisite=("url_consumer_probe_required" if private_oast_available
                                  else "private_oast_backend_required"),
                    confidence=0.2, evidence=surface.discovery_evidence,
                    hypothesis_id=surface.surface_id,
                ))
                continue
            if verdict.outcome is URLConsumerOutcome.NO_CALLBACK_OBSERVED:
                continue
            confirmed = verdict.outcome in {
                URLConsumerOutcome.CALLBACK_CONFIRMED,
                URLConsumerOutcome.DELAYED_CALLBACK_CONFIRMED,
            }
            technique = (
                HunterTechnique.SSRF_ASYNC_CALLBACK
                if verdict.outcome is URLConsumerOutcome.DELAYED_CALLBACK_CONFIRMED
                else HunterTechnique.SSRF_URL_CONSUMER
            )
            if confirmed and (
                verdict.redirect_behavior != "not_observed"
                or verdict.dns_behavior == "changed_across_resolution"
            ):
                technique = HunterTechnique.SSRF_REDIRECT_DNS_BEHAVIOR
            opportunities.append(_opportunity(
                program=program, scope_digest=scope_digest,
                authorization_id=authorization_id, asset_locator=asset_locator,
                surface=surface, technique=technique,
                prerequisite="ready" if confirmed else "oast_polling_or_scope_required",
                confidence=verdict.confidence, evidence=verdict.evidence,
                hypothesis_id=verdict.verdict_id,
                metadata={"oracle_outcome": verdict.outcome.value,
                          "callback_delay_seconds": verdict.callback_delay_seconds,
                          "redirect_behavior": verdict.redirect_behavior,
                          "dns_behavior": verdict.dns_behavior},
            ))
        opportunity_rows = tuple(sorted(opportunities, key=lambda row: row.opportunity_id))
        self._persist(graph, asset_locator, surface_rows, verdicts, opportunity_rows)
        selected = tuple(row[0] for row in allocate(
            list(opportunity_rows), capacity=capacity,
            exploration_fraction=exploration_fraction,
        ))
        missions = tuple(compile_opportunity_mission(row) for row in selected)
        return PhaseCResult(surface_rows, verdicts, opportunity_rows, selected, missions)

    @staticmethod
    def _persist(graph, asset_locator, surfaces, verdicts, opportunities) -> None:
        asset_id = "asset:" + sha256(asset_locator.encode()).hexdigest()[:16]
        graph.upsert_node(asset_id, "api", identifier=asset_locator)
        for row in surfaces:
            graph.upsert_node(row.surface_id, "url_consumer", route=row.route,
                              parameter=row.parameter, consumer_kind=row.kind.value,
                              delivery=row.delivery.value, authorized=row.authorized)
            graph.connect(GraphEdge(row.surface_id, "belongs_to", asset_id,
                                    "|".join(row.discovery_evidence), 0.8))
        for row in verdicts:
            graph.upsert_node(row.verdict_id, "oracle_result", outcome=row.outcome.value,
                              confidence=row.confidence, redirect_behavior=row.redirect_behavior,
                              dns_behavior=row.dns_behavior)
            graph.connect(GraphEdge(row.verdict_id, "evaluates", row.probe.surface.surface_id,
                                    "|".join(row.evidence), row.confidence))
        for row in opportunities:
            graph.upsert_node(row.opportunity_id, "hunt_opportunity",
                              technique=row.metadata.get("technique", ""),
                              prerequisite_state=row.prerequisite_state)
            graph.connect(GraphEdge(row.opportunity_id, "targets", asset_id,
                                    "|".join(row.provenance), row.p_valid))


__all__ = ["HunterIntelligencePhaseC", "PhaseCResult"]
