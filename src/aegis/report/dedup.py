"""Duplicate detection before submission (Master Prompt §8; P1 #26).

Checks a finding against (a) prior *internal* findings by exact fingerprint and
(b) a corpus of *public* disclosed reports by a coarse (host, CWE) match. On
mature programs most submissions are duplicates; catching them here avoids
wasted research and reputation damage.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from aegis.model import Finding


@dataclass
class DuplicateResult:
    is_duplicate: bool
    matches: list[tuple[str, str]] = field(default_factory=list)  # (source, id)


def is_duplicate(
    finding: Finding,
    *,
    prior_findings: Iterable[Finding] | None = None,
    corpus: Iterable | None = None,
) -> DuplicateResult:
    matches: list[tuple[str, str]] = []

    fp = finding.fingerprint()
    for pf in prior_findings or []:
        if pf.fingerprint() == fp and pf.candidate_id != finding.candidate_id:
            matches.append(("internal", pf.candidate_id))

    host = finding.asset.lower().strip()
    cwe = finding.cwe.upper().strip()
    if cwe and host:
        for report in corpus or []:
            r_cwe = (getattr(report, "cwe", "") or "").upper()
            r_asset = (getattr(report, "asset_identifier", "") or "").lower()
            if r_cwe == cwe and (host in r_asset or r_asset in host):
                matches.append(("public", getattr(report, "report_id", "?")))

    return DuplicateResult(is_duplicate=bool(matches), matches=matches)
