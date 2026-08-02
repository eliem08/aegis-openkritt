"""Knowledge base — learning from past disclosed bug-bounty reports (§3, §8, §12).

Ingest past reports into a :class:`ReportCorpus`, derive :class:`CorpusInsights`
(weakness frequency, per-asset-type patterns, historical priors), and feed those
back into finding prioritisation (:mod:`enrichment`) and planning
(:class:`KnowledgeAwarePlanner`).
"""

from .corpus import ReportCorpus
from .enrichment import enrich_candidate, normalized_prior, reprioritize_finding
from .hackerone import map_hacktivity, map_hacktivity_report
from .insights import CorpusInsights, WeaknessStat
from .planner import KnowledgeAwarePlanner
from .report import DisclosedReport, Severity, normalize_cwe

__all__ = [
    "ReportCorpus",
    "CorpusInsights",
    "WeaknessStat",
    "DisclosedReport",
    "Severity",
    "normalize_cwe",
    "enrich_candidate",
    "reprioritize_finding",
    "normalized_prior",
    "map_hacktivity",
    "map_hacktivity_report",
    "KnowledgeAwarePlanner",
]
