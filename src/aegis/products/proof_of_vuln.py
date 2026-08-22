"""Proof-of-Vuln — reproduce or refute a single finding.

Product B4. Takes any finding (from a scanner, a pentest, a bounty report, or an Aegis hunt),
validates the claim against the pinned source, and — when the checkout can be stood up locally —
reproduces it against a deterministic oracle. Answers the market's most expensive question:
*"Is this actually real?"*

Boundary: reproduction is local-only and opt-in (``AEGIS_ALLOW_REPRO=1`` + a docker-compose in the
checkout). Without it, a finding can still be validator-confirmed against source but not promoted
past ``confirmed``.
"""

from __future__ import annotations

from .models import ProductFinding, ProductResult, to_report, to_rows
from .ports import Ports, default_ports


def run(finding, repo_dir: str, *, ports: Ports | None = None, reproduce: bool = True,
        repository: str = "") -> ProductResult:
    """Validate (and optionally reproduce) one or more findings against ``repo_dir``.

    ``finding`` may be a single row, a list of rows, or a full report dict.
    """
    ports = ports or default_ports()
    rows = to_rows(finding)
    report = to_report(rows, repository=repository)

    validated = ports.validate_report(report, repo_dir)
    repro_summary = {"attempted": False, "reason": "reproduce=False"}
    if reproduce:
        repro_summary = ports.reproduce_report(validated, repo_dir)

    out_rows = validated.get("vulnerabilities") or rows
    findings = [ProductFinding.from_row(r, index=i) for i, r in enumerate(out_rows)]
    result = ProductResult(
        product="proof-of-vuln",
        target=repository or repo_dir,
        findings=findings,
        stats={
            "input": len(rows),
            "reproduction": repro_summary,
        },
    )
    return result
