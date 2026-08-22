"""Repo Autopilot — continuous governed review of your own code.

Product A1. Runs the full engine (arsenal + LLM ensemble + funnel + citation validator) over a
repository the customer owns, then — opt-in and local-only — reproduces the confirmed findings.
Because the code is the customer's own, authorization is automatic and the "source-review only, no
live-attack" boundary is a feature, not a limit.

``reproduced_only=True`` returns only findings a deterministic oracle actually reproduced — the
highest-trust mode, suitable for auto-filing tickets.
"""

from __future__ import annotations

from .models import ProductFinding, ProductResult
from .ports import Ports, default_ports


def run(repo: str, *, repo_dir: str | None = None, ports: Ports | None = None,
        files: int = 12, samples: int = 2, reproduce: bool = True,
        reproduced_only: bool = False, repository: str = "") -> ProductResult:
    ports = ports or default_ports()
    repository = repository or repo

    report = ports.hunt(repo, repo_dir=repo_dir, files=files, samples=samples)
    repro_summary = {"attempted": False, "reason": "reproduce=False"}
    if reproduce:
        # reproduction needs the local checkout; use repo_dir when we have it
        target_dir = repo_dir or ((report.get("scan") or {}).get("clone_path") or "")
        if target_dir:
            repro_summary = ports.reproduce_report(report, target_dir)

    rows = report.get("vulnerabilities") or []
    findings = [ProductFinding.from_row(r, index=i) for i, r in enumerate(rows)]
    # Autopilot ships conclusions, not scanner noise: drop raw refuted/unresolved candidates.
    findings = [f for f in findings if f.evidence.verdict in ("confirmed", "reproduced")]
    if reproduced_only:
        findings = [f for f in findings if f.evidence.verdict == "reproduced"]

    return ProductResult(
        product="repo-autopilot",
        target=repository,
        findings=findings,
        stats={
            "files_analyzed": len((report.get("scan") or {}).get("selected_files") or []) or files,
            "raw_rows": len(rows),
            "reproduction": repro_summary,
            "reproduced_only": reproduced_only,
        },
    )
