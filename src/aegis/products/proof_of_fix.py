"""Proof-of-Fix — prove a patch actually closes the bug.

Product B5. Reproduces a finding on the *vulnerable* checkout (must trigger) and on the *fixed*
checkout (must NOT trigger). Verifies closure by execution, not by "marked resolved". Answers the
second-most-expensive question: *"Did we actually fix it?"*

Verdicts:
  * ``fix_confirmed``   — triggered on vulnerable, no longer triggers on fixed
  * ``still_vulnerable``— still triggers on the fixed checkout
  * ``fix_unproven``    — could not establish the baseline (no repro on the vulnerable checkout)
"""

from __future__ import annotations

import copy

from .models import (
    Evidence,
    ProductFinding,
    ProductResult,
    to_report,
    to_rows,
)
from .ports import Ports, default_ports


def _fingerprint(row: dict) -> tuple:
    ja = row.get("json_answer") or {}
    return (str(ja.get("file_path") or row.get("path") or ""),
            int(ja.get("line") or row.get("line") or 0) // 5,
            str(ja.get("vulnerability_type") or row.get("cwe") or ""))


def _triggered(row: dict) -> bool:
    return (row.get("reproduction") or {}).get("verdict") == "reproduced"


def run(finding, repo_dir_vuln: str, repo_dir_fixed: str, *, ports: Ports | None = None,
        repository: str = "") -> ProductResult:
    ports = ports or default_ports()
    rows = to_rows(finding)

    # Baseline on the vulnerable checkout: validate, then reproduce.
    vuln_report = to_report(copy.deepcopy(rows), repository=repository)
    vuln_validated = ports.validate_report(vuln_report, repo_dir_vuln)
    vuln_summary = ports.reproduce_report(vuln_validated, repo_dir_vuln)
    vuln_rows = vuln_validated.get("vulnerabilities") or rows

    # Candidate fix: reproduce the same (now validator-confirmed) rows on the fixed checkout.
    fixed_report = to_report(copy.deepcopy(vuln_rows), repository=repository)
    fixed_summary = ports.reproduce_report(fixed_report, repo_dir_fixed)
    fixed_by_fp = {_fingerprint(r): r for r in (fixed_report.get("vulnerabilities") or [])}

    findings: list[ProductFinding] = []
    tally = {"fix_confirmed": 0, "still_vulnerable": 0, "fix_unproven": 0}
    for i, vrow in enumerate(vuln_rows):
        fx = fixed_by_fp.get(_fingerprint(vrow), {})
        v_trig, f_trig = _triggered(vrow), _triggered(fx)
        if not v_trig:
            verdict, detail = "fix_unproven", "no reproduction on the vulnerable checkout — baseline not established"
        elif f_trig:
            verdict, detail = "still_vulnerable", "the finding still reproduces on the fixed checkout"
        else:
            verdict, detail = "fix_confirmed", "reproduced on vulnerable, no longer reproduces on fixed"
        tally[verdict] += 1
        pf = ProductFinding.from_row(vrow, index=i)
        pf.evidence = Evidence(stage="fix_verified", verdict=verdict, detail=detail)
        findings.append(pf)

    return ProductResult(
        product="proof-of-fix",
        target=repository or f"{repo_dir_vuln} -> {repo_dir_fixed}",
        findings=findings,
        stats={
            "fix_verdict": tally,
            "vulnerable_reproduction": vuln_summary,
            "fixed_reproduction": fixed_summary,
        },
    )
