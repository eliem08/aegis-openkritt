"""Server-side URL consumer discovery and scoped OAST correlation intelligence."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from hashlib import sha256


class URLConsumerKind(str, Enum):
    IMPORTER = "importer"
    INTEGRATION = "integration"
    WEBHOOK = "webhook"
    IMAGE = "image"
    PDF = "pdf"
    LINK_PREVIEW = "link_preview"
    CLOUD_DRIVE = "cloud_drive"
    OTHER = "other"


class ConsumerDelivery(str, Enum):
    SYNCHRONOUS = "synchronous"
    ASYNCHRONOUS = "asynchronous"
    UNKNOWN = "unknown"


class URLConsumerOutcome(str, Enum):
    CALLBACK_CONFIRMED = "callback_confirmed"
    DELAYED_CALLBACK_CONFIRMED = "delayed_callback_confirmed"
    NO_CALLBACK_OBSERVED = "no_callback_observed"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class URLConsumerSurface:
    surface_id: str
    route: str
    parameter: str
    kind: URLConsumerKind
    delivery: ConsumerDelivery = ConsumerDelivery.UNKNOWN
    authorized: bool = False
    discovery_evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CallbackObservation:
    host: str
    protocol: str
    remote_address: str
    observed_at: datetime
    interaction_id: str


@dataclass(frozen=True, slots=True)
class URLConsumerProbe:
    probe_id: str
    surface: URLConsumerSurface
    probe_address: str
    private_oast_domain: str
    requested_at: datetime
    callbacks: tuple[CallbackObservation, ...] = ()
    redirect_chain: tuple[str, ...] = ()
    dns_resolution_sequence: tuple[tuple[str, ...], ...] = ()
    job_correlation: str = ""
    polling_complete: bool = False
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class URLConsumerVerdict:
    verdict_id: str
    outcome: URLConsumerOutcome
    reason: str
    confidence: float
    probe: URLConsumerProbe
    callback_delay_seconds: float | None = None
    redirect_behavior: str = "not_observed"
    dns_behavior: str = "not_observed"
    evidence: tuple[str, ...] = field(default_factory=tuple)


class ServerSideURLConsumerAgent:
    """Classify only exact, tenant-scoped private OAST interactions as confirmation."""

    def analyze(self, probe: URLConsumerProbe) -> URLConsumerVerdict:
        verdict_id = "url-consumer:" + sha256(probe.probe_id.encode()).hexdigest()[:20]
        domain = probe.private_oast_domain.casefold().strip(".")
        address = probe.probe_address.casefold().strip(".")
        in_private_zone = bool(domain) and (
            address == domain or address.endswith("." + domain)
        )
        matches = tuple(
            item for item in probe.callbacks
            if item.host.casefold().strip(".") == address
        ) if in_private_zone else ()
        redirect = self._redirect_behavior(probe.redirect_chain)
        dns = self._dns_behavior(probe.dns_resolution_sequence)
        evidence = tuple(dict.fromkeys((*probe.surface.discovery_evidence, *probe.evidence,
                                        *(item.interaction_id for item in matches))))
        if not probe.surface.authorized:
            return URLConsumerVerdict(
                verdict_id, URLConsumerOutcome.INCONCLUSIVE,
                "surface is not confirmed in scope", 0.0, probe,
                redirect_behavior=redirect, dns_behavior=dns, evidence=evidence,
            )
        if not in_private_zone:
            return URLConsumerVerdict(
                verdict_id, URLConsumerOutcome.INCONCLUSIVE,
                "probe address is not under the configured private OAST domain", 0.0, probe,
                redirect_behavior=redirect, dns_behavior=dns, evidence=evidence,
            )
        if matches:
            first = min(matches, key=lambda item: item.observed_at)
            delay = max(0.0, (first.observed_at - probe.requested_at).total_seconds())
            delayed = probe.surface.delivery is ConsumerDelivery.ASYNCHRONOUS or delay >= 5.0
            return URLConsumerVerdict(
                verdict_id,
                URLConsumerOutcome.DELAYED_CALLBACK_CONFIRMED if delayed
                else URLConsumerOutcome.CALLBACK_CONFIRMED,
                "exact outstanding private OAST probe received a correlated callback",
                0.98, probe, delay, redirect, dns, evidence,
            )
        if not probe.polling_complete:
            return URLConsumerVerdict(
                verdict_id, URLConsumerOutcome.INCONCLUSIVE,
                "callback polling window is still open", 0.0, probe,
                redirect_behavior=redirect, dns_behavior=dns, evidence=evidence,
            )
        return URLConsumerVerdict(
            verdict_id, URLConsumerOutcome.NO_CALLBACK_OBSERVED,
            "bounded polling completed without a matching callback; this is not proof of safety",
            0.2, probe, redirect_behavior=redirect, dns_behavior=dns, evidence=evidence,
        )

    @staticmethod
    def _redirect_behavior(chain: tuple[str, ...]) -> str:
        if len(chain) < 2:
            return "not_observed"
        return "followed" if chain[0] != chain[-1] else "loop_or_normalized"

    @staticmethod
    def _dns_behavior(sequence: tuple[tuple[str, ...], ...]) -> str:
        normalized = tuple(tuple(sorted(set(row))) for row in sequence if row)
        if not normalized:
            return "not_observed"
        return "changed_across_resolution" if len(set(normalized)) > 1 else "stable"


def surface_from_route(
    *, route: str, parameter: str, authorized: bool,
    evidence: tuple[str, ...], delivery: ConsumerDelivery = ConsumerDelivery.UNKNOWN,
) -> URLConsumerSurface:
    blob = f"{route} {parameter}".casefold()
    kinds = (
        (URLConsumerKind.WEBHOOK, ("webhook", "callback")),
        (URLConsumerKind.IMAGE, ("image", "avatar", "logo")),
        (URLConsumerKind.PDF, ("pdf", "document")),
        (URLConsumerKind.LINK_PREVIEW, ("preview", "unfurl", "link")),
        (URLConsumerKind.CLOUD_DRIVE, ("drive", "dropbox", "onedrive")),
        (URLConsumerKind.IMPORTER, ("import", "feed", "source")),
        (URLConsumerKind.INTEGRATION, ("integration", "connector")),
    )
    kind = next((candidate for candidate, words in kinds if any(word in blob for word in words)),
                URLConsumerKind.OTHER)
    surface_id = "url-surface:" + sha256(f"{route}\x1f{parameter}".encode()).hexdigest()[:20]
    return URLConsumerSurface(surface_id, route, parameter, kind, delivery,
                              authorized, evidence)


__all__ = [
    "CallbackObservation", "ConsumerDelivery", "ServerSideURLConsumerAgent",
    "URLConsumerKind", "URLConsumerOutcome", "URLConsumerProbe", "URLConsumerSurface",
    "URLConsumerVerdict", "surface_from_route",
]
