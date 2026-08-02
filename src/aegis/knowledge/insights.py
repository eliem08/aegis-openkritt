"""Insights and historical priors derived from a report corpus (§8).

Turns raw disclosed reports into signal: which weaknesses appear most often,
how that varies by asset type, and a **base-rate prior** per weakness class that
feeds finding prioritisation and planning. This is the historical-enrichment
analogue of KEV/EPSS the operating prompt calls for, learned from real reports.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .corpus import ReportCorpus


@dataclass
class WeaknessStat:
    key: str  # CWE-id or weakness name
    weakness: str
    count: int
    share: float  # fraction of the (sub)population
    avg_bounty: float | None = None
    max_severity: str = "none"


def _summarize(reports: list, total: int) -> list[WeaknessStat]:
    groups: dict[str, list] = defaultdict(list)
    labels: dict[str, str] = {}
    for r in reports:
        groups[r.weakness_key].append(r)
        labels.setdefault(r.weakness_key, r.weakness or r.weakness_key)

    stats: list[WeaknessStat] = []
    for key, members in groups.items():
        bounties = [m.bounty for m in members if m.bounty is not None]
        max_sev = max((m.severity for m in members), default=None)
        stats.append(
            WeaknessStat(
                key=key,
                weakness=labels[key],
                count=len(members),
                share=(len(members) / total) if total else 0.0,
                avg_bounty=(sum(bounties) / len(bounties)) if bounties else None,
                max_severity=max_sev.label if max_sev is not None else "none",
            )
        )
    stats.sort(key=lambda s: (s.count, s.share), reverse=True)
    return stats


@dataclass
class CorpusInsights:
    corpus: ReportCorpus
    _cache: dict = field(default_factory=dict, repr=False)

    def weakness_frequency(self) -> list[WeaknessStat]:
        reports = self.corpus.reports
        return _summarize(reports, len(reports))

    def top_weaknesses(self, n: int = 5) -> list[WeaknessStat]:
        return self.weakness_frequency()[:n]

    def by_asset_type(self) -> dict[str, list[WeaknessStat]]:
        buckets: dict[str, list] = defaultdict(list)
        for r in self.corpus:
            buckets[r.asset_type or "unknown"].append(r)
        return {at: _summarize(members, len(members)) for at, members in buckets.items()}

    def priors_for(
        self, *, asset_type: str | None = None, program: str | None = None
    ) -> dict[str, float]:
        """Base-rate prior P(weakness) over the selected sub-population.

        Returns ``{weakness_key: share}`` summing to ~1 over the subset. Empty
        subset -> empty dict (callers fall back to a neutral prior).
        """
        subset = self.corpus.filter(
            asset_type=asset_type if asset_type else None,
            program=program if program else None,
        )
        total = len(subset)
        if not total:
            return {}
        return {s.key: s.share for s in _summarize(subset, total)}

    def base_rate(self, weakness_key: str, *, asset_type: str | None = None) -> float:
        """Historical share of one weakness class (0..1) in the sub-population."""
        return self.priors_for(asset_type=asset_type).get(weakness_key.upper(), 0.0)

    def program_summary(self, program: str) -> dict:
        subset = self.corpus.filter(program=program)
        stats = _summarize(subset, len(subset))
        return {
            "program": program,
            "reports": len(subset),
            "top_weaknesses": [(s.key, s.count) for s in stats[:5]],
        }
