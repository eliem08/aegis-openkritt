"""Enrich findings with historical priors (Master Prompt §8).

Blends a finding's ``p_exploit`` with the *normalized* historical base rate of
its weakness class (from the corpus), then recomputes priority and the SSVC
decision. Weaknesses that show up often in past disclosures on the same asset
type are nudged up; unseen ones are left alone. This is deliberately a gentle
blend (default weight 0.3) — history informs, it does not decide.
"""

from __future__ import annotations

from aegis.model import Candidate, Finding, priority_score, ssvc_decision

from .insights import CorpusInsights


def normalized_prior(
    insights: CorpusInsights, cwe: str, *, asset_type: str | None = None
) -> float:
    """Historical share of ``cwe`` scaled so the most common class == 1.0."""
    if not cwe:
        return 0.0
    priors = insights.priors_for(asset_type=asset_type)
    if not priors:
        return 0.0
    top = max(priors.values())
    return (priors.get(cwe.upper(), 0.0) / top) if top else 0.0


def enrich_candidate(
    candidate: Candidate,
    insights: CorpusInsights,
    *,
    weight: float = 0.3,
    asset_type: str | None = None,
) -> Candidate:
    """Return a copy of ``candidate`` with ``p_exploit`` blended toward the
    historical prior for its CWE. No-op if the CWE is unseen in the corpus."""
    if not 0.0 <= weight <= 1.0:
        raise ValueError("weight must be in [0, 1]")
    prior = normalized_prior(insights, candidate.cwe, asset_type=asset_type)
    if prior <= 0:
        return candidate
    blended = (1 - weight) * candidate.p_exploit + weight * prior
    return candidate.model_copy(update={"p_exploit": min(1.0, max(0.0, blended))})


def reprioritize_finding(
    finding: Finding,
    insights: CorpusInsights,
    *,
    weight: float = 0.3,
    asset_type: str | None = None,
) -> Finding:
    """Enrich a finding's p_exploit from history, then recompute priority/SSVC."""
    enriched = enrich_candidate(finding, insights, weight=weight, asset_type=asset_type)
    prio = priority_score(enriched)
    return finding.model_copy(
        update={
            "p_exploit": enriched.p_exploit,
            "priority": prio,
            "ssvc": ssvc_decision(prio),
        }
    )
