"""Aegis-Bench — deterministic in-repo detector regression benchmark.

`run_bench()` measures the bundled scanners against a labeled vulnerable/clean corpus and
reports recall/precision/FP-rate from real scanner output. CLI: `python -m aegis.bench`.
"""

from .corpus import CASES, Case
from .runner import BenchResult, CaseResult, run_bench

__all__ = ["CASES", "Case", "BenchResult", "CaseResult", "run_bench"]
