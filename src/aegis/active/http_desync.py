"""HTTP request desynchronization / smuggling research primitives.

This module is intentionally transport-agnostic and does not emit raw request-smuggling
payloads or contact a target.  It turns already-collected protocol/intermediary observations
into bounded hypotheses that the active planner can route through Jarvis policy.

The live-validation boundary remains outside this module: any network request must be derived
from discovered assets and separately authorized by ``ProposalPolicy``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable


class DesyncFamily(StrEnum):
    CL_TE = "cl_te"
    TE_CL = "te_cl"
    TE_TE = "te_te"
    H2_DOWNGRADE = "h2_downgrade"
    PARSER_DIFFERENTIAL = "parser_differential"


@dataclass(frozen=True)
class DesyncObservation:
    """Benign evidence about one discovered HTTP route/protocol chain.

    The fields describe observations supplied by discovery, passive fingerprinting, a local
    reproduction lab, or an explicitly authorized bounded probe.  No payload is represented.
    """

    route: str
    host: str = ""
    client_protocol: str = ""
    upstream_protocol: str = ""
    has_content_length: bool = False
    has_transfer_encoding: bool = False
    duplicate_content_length: bool = False
    transfer_encoding_variant: bool = False
    intermediary_chain: tuple[str, ...] = ()
    connection_reused: bool = False
    response_desync_signal: bool = False
    timing_anomaly: bool = False
    provenance: str = ""


@dataclass(frozen=True)
class DesyncCandidate:
    route: str
    host: str
    family: DesyncFamily
    confidence: float
    rationale: str
    evidence_count: int
    provenance: tuple[str, ...] = ()


def _protocol(value: str) -> str:
    normalized = str(value or "").strip().lower().replace("http/", "h")
    aliases = {
        "2": "h2",
        "h2.0": "h2",
        "1.1": "h1",
        "h1.1": "h1",
        "1": "h1",
    }
    return aliases.get(normalized, normalized)


def _families(observation: DesyncObservation) -> tuple[DesyncFamily, ...]:
    families: list[DesyncFamily] = []
    client = _protocol(observation.client_protocol)
    upstream = _protocol(observation.upstream_protocol)

    if client == "h2" and upstream.startswith("h1"):
        families.append(DesyncFamily.H2_DOWNGRADE)
    if observation.has_content_length and observation.has_transfer_encoding:
        families.extend((DesyncFamily.CL_TE, DesyncFamily.TE_CL))
    if observation.transfer_encoding_variant:
        families.append(DesyncFamily.TE_TE)
    if observation.duplicate_content_length or observation.response_desync_signal:
        families.append(DesyncFamily.PARSER_DIFFERENTIAL)

    # Stable de-duplication without relying on set ordering.
    return tuple(dict.fromkeys(families))


def _score(observation: DesyncObservation, family: DesyncFamily) -> tuple[float, list[str]]:
    score = 0.20
    reasons: list[str] = []

    if len(observation.intermediary_chain) >= 2:
        score += 0.15
        reasons.append("multiple HTTP intermediaries observed")
    if observation.connection_reused:
        score += 0.08
        reasons.append("connection reuse observed")
    if observation.response_desync_signal:
        score += 0.27
        reasons.append("cross-request response anomaly observed")
    if observation.timing_anomaly:
        score += 0.10
        reasons.append("repeatable timing anomaly observed")
    if observation.duplicate_content_length:
        score += 0.15
        reasons.append("duplicate Content-Length handling observed")
    if observation.transfer_encoding_variant:
        score += 0.12
        reasons.append("non-canonical Transfer-Encoding handling observed")

    if family is DesyncFamily.H2_DOWNGRADE:
        score += 0.18
        reasons.append("HTTP/2 frontend to HTTP/1 upstream translation observed")
    elif family in {DesyncFamily.CL_TE, DesyncFamily.TE_CL}:
        score += 0.12
        reasons.append("both message-length mechanisms are present")
    elif family is DesyncFamily.TE_TE:
        score += 0.10
    elif family is DesyncFamily.PARSER_DIFFERENTIAL:
        score += 0.12

    return min(0.98, score), reasons


def analyze_desync_observations(
    observations: Iterable[DesyncObservation],
    *,
    min_confidence: float = 0.45,
) -> tuple[DesyncCandidate, ...]:
    """Convert protocol evidence into ranked request-desync hypotheses.

    A candidate is not a verified vulnerability.  Verification still requires independent,
    policy-authorized reproduction/differential evidence through the canonical active lane.
    """

    grouped: dict[tuple[str, str, DesyncFamily], list[DesyncObservation]] = {}
    for observation in observations:
        if not observation.route:
            continue
        for family in _families(observation):
            grouped.setdefault((observation.host, observation.route, family), []).append(observation)

    candidates: list[DesyncCandidate] = []
    for (host, route, family), evidence in grouped.items():
        scored = [_score(item, family) for item in evidence]
        confidence = max(score for score, _ in scored)
        # Repeated independent observations increase confidence without allowing count alone to
        # turn weak evidence into certainty.
        if len(evidence) > 1:
            confidence = min(0.98, confidence + min(0.12, 0.04 * (len(evidence) - 1)))
        if confidence < min_confidence:
            continue

        reasons: list[str] = []
        provenance: list[str] = []
        for item, (_, item_reasons) in zip(evidence, scored, strict=True):
            reasons.extend(item_reasons)
            if item.provenance:
                provenance.append(item.provenance)
        rationale = "; ".join(dict.fromkeys(reasons)) or "protocol parser ambiguity observed"
        candidates.append(
            DesyncCandidate(
                route=route,
                host=host,
                family=family,
                confidence=round(confidence, 3),
                rationale=rationale[:500],
                evidence_count=len(evidence),
                provenance=tuple(dict.fromkeys(provenance)),
            )
        )

    return tuple(
        sorted(
            candidates,
            key=lambda item: (-item.confidence, item.host, item.route, item.family.value),
        )
    )


def candidate_routes(candidates: Iterable[DesyncCandidate]) -> tuple[str, ...]:
    """Return de-duplicated discovered routes worth policy-gated validation."""

    return tuple(dict.fromkeys(candidate.route for candidate in candidates if candidate.route))
