"""Bounty Triage Copilot — validate + dedupe incoming bounty reports.

Product B7. For the *receiving* side of a bug-bounty program, drowning in AI-generated
submissions: cluster duplicates, validate each unique claim against source, and rank the queue by
evidence and severity. Sells to program owners and platforms.
"""

from __future__ import annotations

from .models import (
    ProductFinding,
    ProductResult,
    severity_rank,
    to_report,
    to_rows,
)
from .ports import Ports, default_ports


def _fingerprint(row: dict) -> tuple:
    ja = row.get("json_answer") or {}
    return (str(ja.get("file_path") or row.get("path") or "").casefold(),
            int(ja.get("line") or row.get("line") or 0) // 5,
            str(ja.get("vulnerability_type") or row.get("cwe") or "").casefold())


def _rank_key(row: dict):
    conf = row.get("confidence")
    if conf is None:
        conf = (row.get("validation") or {}).get("confidence", 0.0)
    try:
        conf = float(conf)
    except (TypeError, ValueError):
        conf = 0.0
    return (severity_rank(str(row.get("severity") or "medium")), conf)


def run(reports, repo_dir: str | None = None, *, ports: Ports | None = None,
        validate: bool = True, repository: str = "") -> ProductResult:
    ports = ports or default_ports()
    rows = to_rows(reports)

    # Cluster duplicates by (file, ~line, cwe); keep the strongest report as representative.
    clusters: dict[tuple, list[dict]] = {}
    order: list[tuple] = []
    for r in rows:
        fp = _fingerprint(r)
        if fp not in clusters:
            clusters[fp] = []
            order.append(fp)
        clusters[fp].append(r)

    reps: list[dict] = []
    duplicates = 0
    for fp in order:
        group = clusters[fp]
        rep = dict(max(group, key=_rank_key))
        rep["_duplicate_count"] = len(group)
        duplicates += len(group) - 1
        reps.append(rep)

    # Validate unique reports against source when a checkout is available.
    if validate and repo_dir:
        report = to_report(reps, repository=repository)
        validated = ports.validate_report(report, repo_dir)
        reps = validated.get("vulnerabilities") or reps

    findings: list[ProductFinding] = []
    for i, r in enumerate(reps):
        pf = ProductFinding.from_row(r, index=i)
        dupes = int(r.get("_duplicate_count") or 1)
        if dupes > 1:
            pf.meta["duplicate_reports"] = dupes
        findings.append(pf)

    return ProductResult(
        product="bounty-triage",
        target=repository or (repo_dir or "inbox"),
        findings=findings,
        stats={
            "received": len(rows),
            "unique": len(reps),
            "duplicates": duplicates,
        },
    )
