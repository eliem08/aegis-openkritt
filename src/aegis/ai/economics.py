"""Bounty economics for a finding — what it's worth and what to expect.

Turns a validated finding (severity + CWE) and a program's reward tiers into the
numbers a hunter actually wants: the minimum bounty, a likely payout, the top of the
band, and an expected gain that discounts by how confident we are (agent agreement)
and the usual valid/accept odds. So each candidate carries "type, min bounty, likely
gain" instead of a bare severity.
"""

from __future__ import annotations

from dataclasses import dataclass

# Reward tiers per HackerOne program, read off the program pages this session.
# (min, typical, top) USD by severity. Absent programs fall back to DEFAULT.
REWARD_TABLES: dict[str, dict[str, tuple[float, float, float]]] = {
    "matomo": {"critical": (13000, 13000, 13000), "high": (777, 1777, 1777),
               "medium": (333, 777, 777), "low": (333, 333, 333)},
    "vercel-open-source": {"critical": (5250, 6675, 10250), "high": (1250, 4157, 5000),
                           "medium": (250, 882, 1000), "low": (200, 274, 500)},
    "circle-bbp": {"critical": (3000, 4157, 6675), "high": (800, 1674, 3000),
                   "medium": (400, 703, 1000), "low": (150, 333, 400)},
    "blend-labs": {"critical": (7500, 7500, 7500), "high": (3000, 3000, 3000),
                   "medium": (750, 750, 750), "low": (250, 250, 250)},
    "kubernetes": {"critical": (2500, 6675, 10000), "high": (1250, 2500, 5000),
                   "medium": (250, 500, 1000), "low": (100, 200, 200)},
}

DEFAULT_TABLE: dict[str, tuple[float, float, float]] = {
    "critical": (2000, 4000, 10000), "high": (1000, 2000, 5000),
    "medium": (300, 700, 1500), "low": (100, 200, 500),
}

# Baseline odds a validated candidate is actually valid, and (if valid) is accepted/paid.
_P_VALID = 0.35
_P_ACCEPT = 0.60


@dataclass(frozen=True)
class BountyEstimate:
    vuln_type: str
    severity: str
    min_bounty: float
    likely_bounty: float
    top_bounty: float
    agreement: str                 # e.g. "4/5 agents"
    confidence: float              # 0..1, blended from agreement
    expected_gain: float           # likely_bounty × confidence × P(valid) × P(accept)

    def as_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type, "severity": self.severity,
            "min_bounty": round(self.min_bounty), "likely_bounty": round(self.likely_bounty),
            "top_bounty": round(self.top_bounty), "agreement": self.agreement,
            "confidence": round(self.confidence, 2), "expected_gain": round(self.expected_gain),
        }


def _table(handle: str) -> dict[str, tuple[float, float, float]]:
    return REWARD_TABLES.get((handle or "").strip().lower(), DEFAULT_TABLE)


def agreement_confidence(agreement: int, samples: int) -> float:
    """Confidence from agent agreement: a finding 4/5 agents flagged is far more
    trustworthy than 1/5. Bounded to [0.2, 1.0] so a lone flag isn't zeroed out."""
    if samples <= 1:
        return 0.6                                   # single agent — neutral prior
    return round(max(0.2, min(1.0, agreement / samples)), 3)


def estimate(*, vuln_type: str, severity: str, handle: str = "",
             agreement: int = 1, samples: int = 1) -> BountyEstimate:
    sev = (severity or "medium").strip().lower()
    if sev not in ("critical", "high", "medium", "low"):
        sev = "medium"
    lo, mid, hi = _table(handle).get(sev, DEFAULT_TABLE[sev])
    conf = agreement_confidence(agreement, samples)
    expected = mid * conf * _P_VALID * _P_ACCEPT
    return BountyEstimate(
        vuln_type=vuln_type or "unspecified", severity=sev,
        min_bounty=lo, likely_bounty=mid, top_bounty=hi,
        agreement=f"{agreement}/{samples} agents", confidence=conf,
        expected_gain=expected,
    )


def enrich_row(row: dict, handle: str = "") -> dict:
    """Attach a BountyEstimate to a persisted finding row (in place) and return it."""
    answer = row.get("json_answer") or {}
    est = estimate(
        vuln_type=str(answer.get("vulnerability_type") or answer.get("weakness") or ""),
        severity=str(answer.get("severity") or row.get("severity") or "medium"),
        handle=handle,
        agreement=int(row.get("agreement", 1) or 1),
        samples=int(row.get("samples", 1) or 1),
    )
    row["economics"] = est.as_dict()
    return row
