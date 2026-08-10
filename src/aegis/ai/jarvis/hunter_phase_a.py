"""Connected Phase-A hunter intelligence pipeline over the canonical runtime spine."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from hashlib import sha256
from typing import Iterable, Mapping
from urllib.parse import urlsplit

from aegis.ai.agentic_os import GraphEdge
from aegis.ingest.program import ProgramRules
from aegis.scheduler.profit import HuntOpportunity, allocate

from .hunter_techniques import HunterTechnique, technique_definition
from .javascript_intelligence import JavaScriptIntelligenceAgent, JSDiscovery, JSDiscoveryKind
from .mission_scheduler import MissionPlan
from .recon_intelligence import (
    CertificateIntelligenceAgent,
    CertificateRecord,
    CertificateSignal,
    ReconCorrelation,
    ReconCorrelationAgent,
)
from .universal_mission import compile_opportunity_mission


@dataclass(frozen=True)
class PhaseAResult:
    javascript: tuple[JSDiscovery, ...]
    certificate_signals: tuple[CertificateSignal, ...]
    correlations: tuple[ReconCorrelation, ...]
    opportunities: tuple[HuntOpportunity, ...]
    selected: tuple[HuntOpportunity, ...]
    missions: tuple[MissionPlan, ...]


def _host(value: str) -> str:
    return (urlsplit(value).hostname or value).lower().rstrip(".")


def _authorized(host: str, scope: set[str]) -> bool:
    return host in scope or any(item.startswith("*.") and host.endswith(item[1:]) for item in scope)


def _opportunity(
    *, program_id: str, scope_digest: str, authorization_id: str, asset: str,
    asset_kind: str, surface: str, family: str, confidence: float,
    technique: HunterTechnique, evidence: tuple[str, ...], authorized: bool,
    freshness: float = 0.5, metadata: Mapping[str, object] | None = None,
) -> HuntOpportunity:
    definition = technique_definition(technique)
    opportunity_id = "opp:hunter:" + sha256(
        f"{program_id}\x1f{asset}\x1f{technique.value}\x1f{surface}".encode()
    ).hexdigest()[:20]
    return HuntOpportunity(
        opportunity_id,
        program_id=program_id,
        program_handle=program_id,
        asset_id="asset:" + sha256(asset.encode()).hexdigest()[:16],
        asset_kind=asset_kind,
        asset_locator=asset,
        scope_digest=scope_digest,
        authorization_id=authorization_id,
        attack_surface=surface,
        weakness_family=family,
        prerequisite_state="ready" if authorized else "scope_confirmation_required",
        freshness_score=freshness,
        estimated_payout_usd=None,
        p_find=max(0.05, min(0.95, confidence * 0.6)),
        p_valid=max(0.05, min(0.95, confidence)),
        p_unique=0.65,
        p_accepted=0.5,
        p_reproducible=0.7,
        compute_cost_usd=Decimal("0.002"),
        validation_cost_usd=Decimal("0.02"),
        information_gain=max(0.0, min(1.0, confidence)),
        uncertainty=max(0.0, min(1.0, 1.0 - confidence * 0.5)),
        provenance=evidence,
        metadata={
            "technique": technique.value,
            "worker_capability": definition.worker_capability,
            "risk_class": definition.risk_class.value,
            "evidence_requirements": definition.evidence_requirements,
            **dict(metadata or {}),
        },
    )


class HunterIntelligencePhaseA:
    """Observation -> graph -> opportunity -> profit scheduler -> canonical mission."""

    def __init__(self) -> None:
        self.javascript_agent = JavaScriptIntelligenceAgent()
        self.certificate_agent = CertificateIntelligenceAgent()
        self.recon_agent = ReconCorrelationAgent()

    def run(
        self,
        *,
        program: ProgramRules,
        scope_digest: str,
        authorization_id: str,
        graph,
        bundles: Mapping[str, str] | None = None,
        source_maps: Mapping[str, str | Mapping] | None = None,
        certificates: Iterable[CertificateRecord] = (),
        previous_certificates: Iterable[CertificateRecord] = (),
        capacity: int = 5,
        exploration_fraction: float = 0.4,
    ) -> PhaseAResult:
        scope_hosts = set(program.scope_guard_entries())
        javascript = self.javascript_agent.analyze(
            bundles or {}, source_maps=source_maps or {}, scope_hosts=scope_hosts
        )
        self.javascript_agent.persist(javascript, graph)
        certificate_records = tuple(certificates)
        certificate_signals = self.certificate_agent.analyze(
            certificate_records, previous=previous_certificates
        )
        self._persist_certificate_signals(certificate_signals, graph, scope_hosts)
        correlations = self.recon_agent.correlate(
            javascript=javascript,
            certificates=certificate_records,
            authorized_hosts=scope_hosts,
        )
        self.recon_agent.persist(correlations, graph)
        opportunities = self._opportunities(
            program, scope_digest, authorization_id, scope_hosts,
            javascript, certificate_signals, correlations,
        )
        selected_rows = allocate(
            list(opportunities), capacity=capacity,
            exploration_fraction=exploration_fraction,
        )
        selected = tuple(item for item, _score, _lane in selected_rows)
        missions = tuple(compile_opportunity_mission(item) for item in selected)
        return PhaseAResult(
            javascript, certificate_signals, correlations, opportunities, selected, missions
        )

    def run_with_acquisition(
        self,
        *,
        acquirer,
        authorization,
        page_urls: tuple[str, ...],
        ct_domains: tuple[str, ...],
        program: ProgramRules,
        scope_digest: str,
        authorization_id: str,
        graph,
        previous_certificates: Iterable[CertificateRecord] = (),
        capacity: int = 5,
        exploration_fraction: float = 0.4,
    ):
        """Acquire authorized artifacts, then feed the same canonical Phase-A pipeline."""
        acquired = acquirer.acquire(
            page_urls=page_urls, ct_domains=ct_domains,
            scope_hosts=set(program.scope_guard_entries()), authorization=authorization,
        )
        result = self.run(
            program=program, scope_digest=scope_digest, authorization_id=authorization_id,
            graph=graph, bundles=acquired.bundles, source_maps=acquired.source_maps,
            certificates=acquired.certificates,
            previous_certificates=(tuple(previous_certificates)
                                   or acquired.previous_certificates),
            capacity=capacity, exploration_fraction=exploration_fraction,
        )
        return acquired, result

    @staticmethod
    def _persist_certificate_signals(
        signals: Iterable[CertificateSignal], graph, scope: set[str],
    ) -> None:
        for signal in signals:
            graph.upsert_node(
                signal.signal_id, "certificate_signal", signal_kind=signal.kind,
                hostname=signal.hostname, fingerprint=signal.fingerprint,
                observed_at=signal.observed_at.isoformat(), confidence=signal.confidence,
            )
            asset_id = f"asset:domain:{signal.hostname}"
            graph.upsert_node(
                asset_id, "domain", identifier=signal.hostname,
                authorized=_authorized(signal.hostname, scope), inferred=True,
            )
            graph.connect(GraphEdge(
                signal.signal_id, "supports_inference", asset_id,
                "|".join(signal.evidence), signal.confidence,
            ))

    @staticmethod
    def _opportunities(
        program: ProgramRules, scope_digest: str, authorization_id: str, scope: set[str],
        javascript: Iterable[JSDiscovery], certificate_signals: Iterable[CertificateSignal],
        correlations: Iterable[ReconCorrelation],
    ) -> tuple[HuntOpportunity, ...]:
        opportunities: list[HuntOpportunity] = []
        endpoint_kinds = {
            JSDiscoveryKind.JS_ROUTE, JSDiscoveryKind.API_ENDPOINT,
            JSDiscoveryKind.GRAPHQL_ENDPOINT, JSDiscoveryKind.WEBSOCKET_ENDPOINT,
            JSDiscoveryKind.OAUTH_CLIENT, JSDiscoveryKind.REDIRECT_URI,
            JSDiscoveryKind.SOURCE_MODULE,
        }
        for item in javascript:
            if item.kind not in endpoint_kinds:
                continue
            source_host = _host(item.source_url.split("#", 1)[0])
            target_host = _host(item.value) if "://" in item.value else source_host
            technique = item.technique
            opportunities.append(_opportunity(
                program_id=program.handle, scope_digest=scope_digest,
                authorization_id=authorization_id, asset=item.value,
                asset_kind="api" if item.kind in {
                    JSDiscoveryKind.API_ENDPOINT, JSDiscoveryKind.GRAPHQL_ENDPOINT,
                    JSDiscoveryKind.WEBSOCKET_ENDPOINT,
                } else "domain",
                surface=item.kind.value, family="architecture-assumption",
                confidence=item.confidence, technique=technique,
                evidence=(f"{item.source_url}:{item.line}", item.evidence_digest),
                authorized=_authorized(target_host, scope),
                metadata={"discovery_id": item.discovery_id},
            ))
        for item in certificate_signals:
            if item.kind not in {"new_san", "certificate_renewal", "shared_certificate"}:
                continue
            opportunities.append(_opportunity(
                program_id=program.handle, scope_digest=scope_digest,
                authorization_id=authorization_id, asset=item.hostname, asset_kind="domain",
                surface="certificate_change", family="architecture-assumption",
                confidence=item.confidence,
                technique=HunterTechnique.RECON_CT_CLUSTERING,
                evidence=item.evidence, authorized=_authorized(item.hostname, scope),
                freshness=0.95 if item.kind == "new_san" else 0.75,
                metadata={"certificate_signal": item.kind},
            ))
        for item in correlations:
            opportunities.append(_opportunity(
                program_id=program.handle, scope_digest=scope_digest,
                authorization_id=authorization_id, asset=item.target_asset,
                asset_kind="domain", surface=item.relationship_type,
                family="architecture-assumption", confidence=item.confidence,
                technique=item.technique, evidence=item.evidence,
                authorized=item.target_authorized,
                metadata={"correlation_id": item.correlation_id,
                          "reasoning_summary": item.reasoning_summary},
            ))
        return tuple(sorted(
            {item.opportunity_id: item for item in opportunities}.values(),
            key=lambda item: item.opportunity_id,
        ))


__all__ = ["HunterIntelligencePhaseA", "PhaseAResult"]
