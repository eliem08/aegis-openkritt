"""Cache topology and evidence-based cache differential intelligence."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from typing import Mapping


class CacheOutcome(str, Enum):
    SHARED_INFLUENCE_CONFIRMED = "shared_influence_confirmed"
    PRIVATE_DATA_SHARED = "private_data_shared"
    CONSISTENT = "consistent"
    HYPOTHESIS = "hypothesis"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class CacheObservation:
    request_id: str
    client_id: str
    path: str
    status_code: int
    body_digest: str
    markers: tuple[str, ...] = ()
    headers: Mapping[str, str] = None  # type: ignore[assignment]
    authenticated: bool = False
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", dict(self.headers or {}))


@dataclass(frozen=True, slots=True)
class CacheExperiment:
    experiment_id: str
    dimension: str
    marker: str
    prime: CacheObservation
    victim: CacheObservation
    negative_control: CacheObservation | None
    authorized: bool = False
    private_marker: bool = False


@dataclass(frozen=True, slots=True)
class CacheVerdict:
    verdict_id: str
    outcome: CacheOutcome
    reason: str
    confidence: float
    experiment: CacheExperiment
    topology: tuple[str, ...]
    evidence: tuple[str, ...]


class CacheArchitectureAgent:
    """Infer topology and prove shared influence using marker + cross-client controls."""

    def evaluate(self, experiment: CacheExperiment) -> CacheVerdict:
        verdict_id = "cache-verdict:" + sha256(experiment.experiment_id.encode()).hexdigest()[:20]
        observations = tuple(row for row in (
            experiment.prime, experiment.victim, experiment.negative_control
        ) if row is not None)
        evidence = tuple(dict.fromkeys(item for row in observations for item in row.evidence))
        topology = self.infer_topology(*observations)
        if not experiment.authorized:
            return CacheVerdict(verdict_id, CacheOutcome.INCONCLUSIVE,
                                "cache experiment lacks explicit authorization", 0.0,
                                experiment, topology, evidence)
        if experiment.prime.client_id == experiment.victim.client_id:
            return CacheVerdict(verdict_id, CacheOutcome.INCONCLUSIVE,
                                "shared-cache proof requires distinct controlled clients", 0.0,
                                experiment, topology, evidence)
        if not experiment.marker or experiment.marker not in experiment.prime.markers:
            return CacheVerdict(verdict_id, CacheOutcome.INCONCLUSIVE,
                                "prime response does not contain the synthetic marker", 0.0,
                                experiment, topology, evidence)
        marker_shared = experiment.marker in experiment.victim.markers
        negative_clean = (
            experiment.negative_control is not None
            and experiment.marker not in experiment.negative_control.markers
        )
        cache_signal = any(item in topology for item in ("cdn", "proxy", "shared-cache"))
        if marker_shared and negative_clean and cache_signal:
            outcome = (CacheOutcome.PRIVATE_DATA_SHARED if experiment.private_marker
                       else CacheOutcome.SHARED_INFLUENCE_CONFIRMED)
            return CacheVerdict(verdict_id, outcome,
                                "synthetic marker crossed clients through a cache-signaled response",
                                0.97, experiment, topology, evidence)
        if not marker_shared and negative_clean:
            return CacheVerdict(verdict_id, CacheOutcome.CONSISTENT,
                                "marker did not cross the keyed client boundary", 0.85,
                                experiment, topology, evidence)
        return CacheVerdict(verdict_id, CacheOutcome.INCONCLUSIVE,
                            "marker propagation lacks a clean negative control or cache signal",
                            0.0, experiment, topology, evidence)

    @staticmethod
    def infer_topology(*observations: CacheObservation) -> tuple[str, ...]:
        signals = set()
        for row in observations:
            headers = {key.casefold(): value.casefold() for key, value in row.headers.items()}
            if "cf-cache-status" in headers or "x-served-by" in headers:
                signals.add("cdn")
            if "via" in headers or "x-varnish" in headers:
                signals.add("proxy")
            if "age" in headers or "cache-status" in headers or "x-cache" in headers:
                signals.add("shared-cache")
            if "private" in headers.get("cache-control", ""):
                signals.add("private-directive")
            if "no-store" in headers.get("cache-control", ""):
                signals.add("no-store-directive")
        return tuple(sorted(signals))

    @staticmethod
    def deception_hypothesis(
        canonical: CacheObservation, variant: CacheObservation,
    ) -> tuple[CacheOutcome, str]:
        static_suffix = variant.path.casefold().endswith(
            (".css", ".js", ".png", ".jpg", ".ico")
        )
        same_content = canonical.body_digest and canonical.body_digest == variant.body_digest
        topology = CacheArchitectureAgent.infer_topology(variant)
        if canonical.authenticated and static_suffix and same_content and topology:
            return (CacheOutcome.HYPOTHESIS,
                    "authenticated dynamic content is reachable through a cacheable static suffix")
        return CacheOutcome.CONSISTENT, "no evidence-backed cache deception shape observed"


__all__ = [
    "CacheArchitectureAgent", "CacheExperiment", "CacheObservation", "CacheOutcome",
    "CacheVerdict",
]
