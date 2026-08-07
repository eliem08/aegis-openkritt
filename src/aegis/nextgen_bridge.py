"""Bridge existing Aegis observations and candidates into the next-gen core."""
from __future__ import annotations

from decimal import Decimal

from aegis.graph.model import AssetKind, Observation
from aegis.model.finding import Candidate
from aegis.nextgen import (
    AttackSurfaceGraph, EventBus, EventType, FindingLifecycle, SecurityEvent,
    WorkOpportunity, WorkScore, score_opportunity,
)

_ASSET_EVENTS = {
    AssetKind.DOMAIN: EventType.DOMAIN,
    AssetKind.SERVICE: EventType.SERVICE,
    AssetKind.URL: EventType.ENDPOINT,
    AssetKind.ROUTE: EventType.ENDPOINT,
    AssetKind.PARAMETER: EventType.PARAMETER,
}


def event_from_observation(observation: Observation, *, scope_id: str) -> SecurityEvent | None:
    event_type = _ASSET_EVENTS.get(observation.kind)
    if event_type is None:
        return None
    return SecurityEvent(
        type=event_type,
        scope_id=scope_id,
        engagement_id=observation.engagement_id,
        source_module=observation.source,
        asset_key=observation.asset_key,
        confidence=observation.confidence,
        evidence_refs=((observation.raw_ref,) if observation.raw_ref else ()),
        observed_at=observation.observed_at,
        payload={
            **observation.data,
            "scan_id": observation.scan_id,
            "task_id": observation.task_id,
            "provider": observation.provider,
        },
    )


def event_from_candidate(candidate: Candidate, *, scope_id: str,
                         engagement_id: str) -> SecurityEvent:
    evidence = (candidate.evidence_id,) if candidate.evidence_id else ()
    return SecurityEvent(
        type=EventType.STATIC_FINDING,
        scope_id=scope_id,
        engagement_id=engagement_id,
        source_module=candidate.worker or "candidate-import",
        asset_key=f"finding:{candidate.fingerprint()}",
        confidence=candidate.confidence,
        evidence_refs=evidence,
        payload={
            "candidate_id": candidate.candidate_id,
            "affected_asset": candidate.asset,
            "route": candidate.route,
            "parameter": candidate.parameter,
            "code_location": candidate.code_location,
            "dependency": candidate.dependency,
            "cwe": candidate.cwe,
            "impact": candidate.impact,
            "validation_status": "unverified",
        },
    )


def opportunity_from_candidate(
    candidate: Candidate,
    *,
    expected_bounty: Decimal | None,
    duplicate_risk: float = 0.0,
    information_gain: float = 0.0,
    model_cost: Decimal = Decimal(0),
    scanner_cost: Decimal = Decimal(0),
    review_cost: Decimal = Decimal(0),
) -> WorkScore:
    evidence_quality = 1.0 if candidate.evidence_id else 0.55
    item = WorkOpportunity(
        opportunity_id=candidate.candidate_id,
        expected_bounty=expected_bounty,
        p_valid=candidate.confidence,
        p_accepted=min(1.0, max(0.0, candidate.p_exploit)),
        uniqueness=max(0.0, min(1.0, 1.0 - duplicate_risk)),
        duplicate_risk=duplicate_risk,
        report_quality=evidence_quality,
        information_gain=information_gain,
        model_cost=model_cost,
        scanner_cost=scanner_cost,
        review_cost=review_cost,
    )
    return score_opportunity(item)


class IntelligenceRuntime:
    """Scope-bound facade that persists event provenance and graph relationships."""
    def __init__(self, *, scope_id: str, engagement_id: str):
        self.bus = EventBus(scope_id=scope_id, engagement_id=engagement_id)
        self.graph = AttackSurfaceGraph()
        self.scope_id = scope_id
        self.engagement_id = engagement_id
        self.lifecycles: dict[str, FindingLifecycle] = {}

    def ingest_event(self, event: SecurityEvent) -> list[SecurityEvent]:
        emitted = self.bus.publish(event)
        for row in emitted:
            self.graph.ingest(row)
        return emitted

    def ingest_observation(self, observation: Observation) -> list[SecurityEvent]:
        event = event_from_observation(observation, scope_id=self.scope_id)
        if event is None:
            return []
        return self.ingest_event(event)

    def ingest_candidate(self, candidate: Candidate) -> SecurityEvent:
        event = event_from_candidate(
            candidate, scope_id=self.scope_id, engagement_id=self.engagement_id)
        self.ingest_event(event)
        self.lifecycles.setdefault(candidate.candidate_id,
                                   FindingLifecycle(finding_id=candidate.candidate_id))
        return event
