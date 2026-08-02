"""Candidates, canonical findings, and prioritisation (Master Prompt §8).

A ``Candidate`` is a raw observation from a worker. Triage normalises and
deduplicates candidates into ``Finding`` records — the customer-facing schema —
scored by a risk function rather than CVSS alone, then mapped to an SSVC-style
Act / Attend / Track decision.
"""

from __future__ import annotations

import uuid
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class FindingStatus(str, Enum):
    CANDIDATE = "candidate"
    VERIFIED = "verified"
    PATCHED = "patched"
    VERIFIED_FIXED = "verified-fixed"


class SSVCDecision(str, Enum):
    ACT = "act"
    ATTEND = "attend"
    TRACK = "track"


class Candidate(BaseModel):
    """A raw finding produced by a worker, before triage."""

    model_config = ConfigDict(extra="forbid")

    candidate_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    asset: str
    route: str = ""
    parameter: str = ""
    action: str = ""
    worker: str = ""
    observed: str = ""
    expected: str = ""
    impact: str = ""
    preconditions: str = ""
    identity_context: str = ""
    code_location: str = ""
    dependency: str = ""
    cwe: str = ""
    capec: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_id: str | None = None

    # Risk-scoring inputs (§8). Sensible neutral defaults; workers/triage refine.
    p_exploit: float = Field(default=0.5, ge=0.0, le=1.0)
    business_impact: float = Field(default=0.5, ge=0.0, le=1.0)
    asset_criticality: float = Field(default=0.5, ge=0.0, le=1.0)
    exposure_multiplier: float = Field(default=1.0, ge=0.0)

    def fingerprint(self) -> str:
        """Dedup key: same asset/route/parameter/cwe == same family."""
        return "|".join(
            [
                self.asset.lower().strip(),
                self.route.strip(),
                self.parameter.strip(),
                self.cwe.strip().upper(),
            ]
        )


class Finding(Candidate):
    """The canonical, triaged finding (§8)."""

    request_sequence: list[str] = Field(default_factory=list)
    exploit_proof_ref: str | None = None
    duplicate_family: str = ""
    duplicate_count: int = 1
    priority: float = 0.0
    ssvc: SSVCDecision = SSVCDecision.TRACK
    status: FindingStatus = FindingStatus.CANDIDATE


def priority_score(candidate: Candidate) -> float:
    """Priority = P(exploit) × business_impact × asset_criticality ×
    exposure_multiplier × proof_confidence  (§8)."""
    return (
        candidate.p_exploit
        * candidate.business_impact
        * candidate.asset_criticality
        * candidate.exposure_multiplier
        * candidate.confidence
    )


def ssvc_decision(priority: float) -> SSVCDecision:
    """Map a priority score to an SSVC-style decision instead of a static queue."""
    if priority >= 0.5:
        return SSVCDecision.ACT
    if priority >= 0.2:
        return SSVCDecision.ATTEND
    return SSVCDecision.TRACK
