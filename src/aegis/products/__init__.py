"""Aegis product layer — thin, honest product surfaces over the shared hunt engine.

One engine, seven product surfaces. Each product here is a small orchestration over
capabilities that already exist in :mod:`aegis.ai` (the arsenal + LLM funnel, the citation
validator, the local-only reproduction agent, the candidate-reduction dedup) and the
:mod:`aegis.ai.agentic_os` evidence lifecycle. Nothing here invents detection or relaxes a
safety boundary — the products only *compose* the engine and *shape* its output for a buyer.

Group A — sell the finder (own-code AppSec):
  * :func:`aegis.products.repo_autopilot.run`      — continuous governed review of your own repo
  * :func:`aegis.products.pr_gatekeeper.run`       — diff-scoped gate for CI/PR, SARIF out
  * :func:`aegis.products.standing_redteam.run`    — scheduled autopilot + "what's new" digest

Group B — sell the proof (reproduction / validation):
  * :func:`aegis.products.proof_of_vuln.run`       — reproduce/refute any single finding
  * :func:`aegis.products.proof_of_fix.run`        — prove a patch actually closes the bug
  * :func:`aegis.products.slop_filter.run`         — validate/kill another tool's AI findings
  * :func:`aegis.products.bounty_triage.run`       — validate + dedupe incoming bounty reports

Every product returns a :class:`aegis.products.models.ProductResult` and carries the standing
honesty contract: a candidate is unverified until the validator confirms it against source, and
"reproduced" is only ever set by real local execution — never asserted.
"""

from __future__ import annotations

from .models import (
    HONESTY,
    Evidence,
    ProductFinding,
    ProductResult,
    evidence_from_row,
)

__all__ = [
    "Evidence",
    "ProductFinding",
    "ProductResult",
    "evidence_from_row",
    "HONESTY",
]
