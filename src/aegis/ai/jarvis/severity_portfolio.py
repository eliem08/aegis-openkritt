"""Severity-diverse portfolio selection for profitable vulnerability research.

Severity is not a gate. Positive-EV low, medium, and informational candidates
receive reserved exploration slots so they are not crowded out by a large high-
severity queue. Remaining capacity is allocated by economic priority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping

from .weakness_catalog import HuntCandidate, SeverityTier, rank_candidates


@dataclass(frozen=True)
class SeverityPortfolioPolicy:
    max_items: int = 16
    reserved_slots: Mapping[SeverityTier, int] = field(
        default_factory=lambda: {
            SeverityTier.INFO: 1,
            SeverityTier.LOW: 3,
            SeverityTier.MEDIUM: 4,
        }
    )
    minimum_net_usd: float = 0.0


def select_diverse_candidates(
    candidates: Iterable[HuntCandidate],
    policy: SeverityPortfolioPolicy | None = None,
) -> tuple[HuntCandidate, ...]:
    policy = policy or SeverityPortfolioPolicy()
    if policy.max_items <= 0:
        return ()
    ranked = rank_candidates(candidates, minimum_net_usd=policy.minimum_net_usd)
    by_severity: dict[SeverityTier, list[HuntCandidate]] = {tier: [] for tier in SeverityTier}
    for candidate in ranked:
        by_severity[candidate.severity].append(candidate)

    selected: list[HuntCandidate] = []
    seen: set[int] = set()
    for tier in (SeverityTier.INFO, SeverityTier.LOW, SeverityTier.MEDIUM):
        reserve = max(0, int(policy.reserved_slots.get(tier, 0)))
        for candidate in by_severity[tier][:reserve]:
            selected.append(candidate)
            seen.add(id(candidate))
            if len(selected) >= policy.max_items:
                return tuple(selected)

    for candidate in ranked:
        if id(candidate) in seen:
            continue
        selected.append(candidate)
        if len(selected) >= policy.max_items:
            break
    return tuple(selected)
