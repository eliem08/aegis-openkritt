"""PR Gatekeeper — diff-scoped security gate for CI.

Product A2. Runs the engine only over the files a pull request changed, then decides pass/fail:
the gate blocks when a finding whose verdict is in ``fail_on`` lands in the changed set. Emits
SARIF so it drops into GitHub/GitLab code-scanning natively. Comments only when it has real
evidence — the antidote to noisy SAST bots.
"""

from __future__ import annotations

from .models import ProductFinding, ProductResult
from .ports import Ports, default_ports


def run(repo: str, changed_files, *, repo_dir: str | None = None, ports: Ports | None = None,
        files: int = 40, samples: int = 2, reproduce: bool = False,
        fail_on=("confirmed", "reproduced"), repository: str = "") -> ProductResult:
    ports = ports or default_ports()
    repository = repository or repo
    changed = [c for c in (changed_files or []) if c]

    report = ports.hunt(repo, repo_dir=repo_dir, files=files, samples=samples,
                        include_paths=changed)
    if reproduce and repo_dir:
        ports.reproduce_report(report, repo_dir)

    rows = report.get("vulnerabilities") or []
    changed_set = {c.replace("\\", "/") for c in changed}
    findings: list[ProductFinding] = []
    for i, r in enumerate(rows):
        pf = ProductFinding.from_row(r, index=i)
        # keep only findings that land in the changed files (when we know the diff)
        if changed_set and pf.file and pf.file.replace("\\", "/") not in changed_set:
            continue
        findings.append(pf)

    fail_on = tuple(fail_on)
    blocking = [f for f in findings if f.evidence.verdict in fail_on]
    result = ProductResult(
        product="pr-gatekeeper",
        target=repository,
        findings=findings,
        stats={
            "changed_files": len(changed),
            "gate": {
                "failed": bool(blocking),
                "fail_on": list(fail_on),
                "blocking": [f.id for f in blocking],
            },
        },
    )
    return result


def gate_failed(result: ProductResult) -> bool:
    """True when the PR should be blocked."""
    return bool(((result.stats.get("gate") or {}).get("failed")))


def to_sarif(result: ProductResult) -> dict:
    """Minimal SARIF 2.1.0 for GitHub/GitLab code-scanning ingestion."""
    level = {"critical": "error", "high": "error", "medium": "warning",
             "low": "note", "info": "note"}
    rules, results = {}, []
    for f in result.ranked():
        rule_id = f.cwe or "aegis-finding"
        rules.setdefault(rule_id, {"id": rule_id, "name": rule_id,
                                   "shortDescription": {"text": rule_id}})
        results.append({
            "ruleId": rule_id,
            "level": level.get(f.severity.casefold(), "warning"),
            "message": {"text": f"{f.title} [{f.evidence.verdict}] — {f.evidence.detail}".strip(" —")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": max(f.line, 1)},
                }
            }],
            "properties": {"verdict": f.evidence.verdict, "stage": f.evidence.stage,
                           "confidence": f.confidence},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Aegis PR Gatekeeper",
                                "informationUri": "https://github.com/eliem08/aegis-openkritt",
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }
