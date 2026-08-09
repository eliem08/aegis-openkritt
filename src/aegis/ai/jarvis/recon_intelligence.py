"""Evidence-backed recon correlation and certificate-transparency intelligence."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from itertools import combinations
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from ..agentic_os import GraphEdge
from .hunter_techniques import HunterTechnique
from .javascript_intelligence import JSDiscovery, JSDiscoveryKind


def _host(value: str) -> str:
    return (urlsplit(value).hostname or value).lower().rstrip(".")


def _authorized(host: str, scope: set[str]) -> bool:
    return host in scope or any(item.startswith("*.") and host.endswith(item[1:]) for item in scope)


@dataclass(frozen=True)
class CertificateRecord:
    fingerprint: str
    sans: tuple[str, ...]
    issuer: str
    subject: str
    serial: str
    not_before: datetime
    not_after: datetime
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    source: str = "certificate_transparency"


@dataclass(frozen=True)
class CertificateSignal:
    signal_id: str
    kind: str
    hostname: str
    fingerprint: str
    observed_at: datetime
    confidence: float
    reasoning: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class ReconCorrelation:
    correlation_id: str
    source_asset: str
    target_asset: str
    relationship_type: str
    confidence: float
    observed_at: datetime
    reasoning_summary: str
    evidence: tuple[str, ...]
    technique: HunterTechnique
    target_authorized: bool
    metadata: Mapping[str, Any] = field(default_factory=dict)


def _id(prefix: str, *parts: str) -> str:
    return prefix + ":" + sha256("\x1f".join(parts).encode()).hexdigest()[:24]


class CertificateIntelligenceAgent:
    """Compare CT snapshots and emit temporal signals without performing acquisition."""

    def analyze(
        self,
        current: Iterable[CertificateRecord],
        *,
        previous: Iterable[CertificateRecord] = (),
    ) -> tuple[CertificateSignal, ...]:
        current_records = tuple(current)
        previous_records = tuple(previous)
        current_sans = {san.lower().rstrip(".") for record in current_records for san in record.sans}
        previous_sans = {san.lower().rstrip(".") for record in previous_records for san in record.sans}
        signals: list[CertificateSignal] = []
        for host in sorted(current_sans - previous_sans):
            record = next(item for item in current_records if host in {_host(x) for x in item.sans})
            signals.append(self._signal(
                "new_san", host, record, 0.92,
                "hostname newly appeared in the observed certificate set",
            ))
        for host in sorted(previous_sans - current_sans):
            record = next(item for item in previous_records if host in {_host(x) for x in item.sans})
            signals.append(self._signal(
                "san_disappeared", host, record, 0.75,
                "hostname disappeared from the current certificate set; absence is not deletion",
            ))
        previous_by_sans = {
            tuple(sorted(_host(san) for san in record.sans)): record for record in previous_records
        }
        for record in current_records:
            sans_key = tuple(sorted(_host(san) for san in record.sans))
            old = previous_by_sans.get(sans_key)
            if old and old.fingerprint != record.fingerprint:
                signals.append(self._signal(
                    "certificate_renewal", sans_key[0] if sans_key else record.subject,
                    record, 0.9, "same SAN cluster observed with a new certificate fingerprint",
                    extra=(old.fingerprint,),
                ))
            if len(sans_key) > 1:
                for host in sans_key:
                    signals.append(self._signal(
                        "shared_certificate", host, record, 0.84,
                        "multiple hostnames are covered by one observed certificate",
                        extra=tuple(item for item in sans_key if item != host),
                    ))
        return tuple(sorted(
            {signal.signal_id: signal for signal in signals}.values(),
            key=lambda signal: (signal.kind, signal.hostname, signal.signal_id),
        ))

    @staticmethod
    def _signal(
        kind: str, hostname: str, record: CertificateRecord, confidence: float,
        reasoning: str, extra: tuple[str, ...] = (),
    ) -> CertificateSignal:
        evidence = (
            f"fingerprint:{record.fingerprint}", f"serial:{record.serial}",
            f"issuer:{record.issuer}", f"observed:{record.observed_at.isoformat()}", *extra,
        )
        return CertificateSignal(
            _id("ct", kind, hostname, record.fingerprint), kind, hostname,
            record.fingerprint, record.observed_at, confidence, reasoning, evidence,
        )


class ReconCorrelationAgent:
    """Correlate public observations while keeping inference separate from authorization."""

    def correlate(
        self,
        *,
        javascript: Iterable[JSDiscovery] = (),
        certificates: Iterable[CertificateRecord] = (),
        authorized_hosts: set[str] | None = None,
    ) -> tuple[ReconCorrelation, ...]:
        scope = {item.lower().rstrip(".") for item in (authorized_hosts or set())}
        js = tuple(javascript)
        correlations: list[ReconCorrelation] = []

        tracking: dict[str, list[JSDiscovery]] = {}
        for item in js:
            if item.kind is JSDiscoveryKind.PUBLIC_TRACKING_ID:
                tracking.setdefault(item.value.lower(), []).append(item)
            if item.kind is JSDiscoveryKind.HOST_REFERENCE:
                source = _host(item.source_url.split("#", 1)[0])
                target = _host(item.value)
                if source != target:
                    correlations.append(self._correlation(
                        source, target, "references_host", item.confidence, item.observed_at,
                        "JavaScript artifact contains an exact hostname reference",
                        (f"{item.source_url}:{item.line}", item.evidence_digest),
                        HunterTechnique.JS_ROUTE_RECOVERY, scope,
                    ))
        for tracking_id, observations in tracking.items():
            by_host = {_host(item.source_url.split("#", 1)[0]): item for item in observations}
            for source, target in combinations(sorted(by_host), 2):
                evidence = (
                    f"tracking-digest:{sha256(tracking_id.encode()).hexdigest()}",
                    f"{by_host[source].source_url}:{by_host[source].line}",
                    f"{by_host[target].source_url}:{by_host[target].line}",
                )
                correlations.append(self._correlation(
                    source, target, "shares_public_tracking_id", 0.72,
                    max(by_host[source].observed_at, by_host[target].observed_at),
                    "two public sites expose the same tracking identifier; this is correlation, "
                    "not ownership proof", evidence,
                    HunterTechnique.RECON_ANALYTICS_CORRELATION, scope,
                    metadata={"identifier_digest": sha256(tracking_id.encode()).hexdigest()},
                ))

        for record in certificates:
            hosts = sorted({_host(item) for item in record.sans})
            for source, target in combinations(hosts, 2):
                correlations.append(self._correlation(
                    source, target, "shares_certificate", 0.8, record.observed_at,
                    "hostnames appear in the same certificate SAN set; this is not ownership proof",
                    (f"fingerprint:{record.fingerprint}", f"serial:{record.serial}"),
                    HunterTechnique.RECON_CT_CLUSTERING, scope,
                    metadata={"issuer": record.issuer, "subject": record.subject},
                ))
        return tuple(sorted(
            {item.correlation_id: item for item in correlations}.values(),
            key=lambda item: (item.relationship_type, item.source_asset, item.target_asset),
        ))

    @staticmethod
    def _correlation(
        source: str, target: str, relation: str, confidence: float, observed_at: datetime,
        reasoning: str, evidence: tuple[str, ...], technique: HunterTechnique,
        scope: set[str], metadata: Mapping[str, Any] | None = None,
    ) -> ReconCorrelation:
        return ReconCorrelation(
            _id("corr", relation, source, target, *evidence), source, target, relation,
            confidence, observed_at, reasoning, evidence, technique,
            _authorized(target, scope), dict(metadata or {}),
        )

    @staticmethod
    def persist(correlations: Iterable[ReconCorrelation], graph) -> None:
        for item in correlations:
            source_id = f"asset:domain:{item.source_asset}"
            target_id = f"asset:domain:{item.target_asset}"
            graph.upsert_node(source_id, "domain", identifier=item.source_asset)
            graph.upsert_node(
                target_id, "domain", identifier=item.target_asset,
                authorized=item.target_authorized, inferred=True,
                observed_at=item.observed_at.isoformat(),
            )
            graph.connect(GraphEdge(
                source_id, item.relationship_type, target_id,
                "|".join(item.evidence), item.confidence,
            ))


__all__ = [
    "CertificateIntelligenceAgent",
    "CertificateRecord",
    "CertificateSignal",
    "ReconCorrelation",
    "ReconCorrelationAgent",
]
