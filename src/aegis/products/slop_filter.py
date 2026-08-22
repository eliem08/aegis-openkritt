"""Slop Filter — validate/kill another tool's AI findings.

Product B6. Sits on top of *other* tools' output (a SARIF export, another AI scanner's JSON, a
consultant's list) and runs each claim through Aegis's citation validator — and, when enabled,
local reproduction. Splits the pile into ``kept`` (confirmed/reproduced) and ``killed``
(refuted/unresolved). Monetizes the market's #1 pain: AI false-positive fatigue.
"""

from __future__ import annotations

from .models import ProductFinding, ProductResult, to_report, to_rows
from .ports import Ports, default_ports


def run(findings, repo_dir: str, *, ports: Ports | None = None, reproduce: bool = False,
        repository: str = "") -> ProductResult:
    ports = ports or default_ports()
    rows = to_rows(findings)
    input_n = len(rows)
    report = to_report(rows, repository=repository)

    validated = ports.validate_report(report, repo_dir)
    if reproduce:
        ports.reproduce_report(validated, repo_dir)

    out_rows = validated.get("vulnerabilities") or rows
    pfs = [ProductFinding.from_row(r, index=i) for i, r in enumerate(out_rows)]
    kept = [f for f in pfs if f.evidence.verdict in ("confirmed", "reproduced")]
    killed = [f for f in pfs if f.evidence.verdict in ("refuted", "unresolved")]

    return ProductResult(
        product="slop-filter",
        target=repository or repo_dir,
        findings=pfs,
        stats={
            "input": input_n,
            "kept": len(kept),
            "killed": len(killed),
            "kill_rate": round(len(killed) / input_n, 3) if input_n else 0.0,
        },
    )
