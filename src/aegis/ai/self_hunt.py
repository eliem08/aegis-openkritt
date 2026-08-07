"""Authorized local self-audit.

Runs the installed scanners over a LOCAL checkout the operator already controls (a
repository-owner self-audit — no third-party target, no network exploitation), reduces the raw
scanner observations to a small ranked set of candidate *families* via the deterministic
:mod:`aegis.ai.candidate_reduction` funnel, and persists an auditable JSON report.

Boundary: candidates only. Nothing here is promoted past the ``candidate`` evidence stage,
nothing is reproduced, and nothing is submitted. Scanner output is unverified by definition.
"""

from __future__ import annotations

import collections
import json
import os
from pathlib import Path

_DEFAULT_LANES = ("code", "secrets", "deps")


def _reason_counts(suppressed) -> dict:
    c = collections.Counter(s.reason.split(" (")[0] for s in suppressed)
    return dict(c.most_common())


def build_report(target: str, authorization: str, results, rows, reduction) -> dict:
    """Shape a self-hunt report from scan results + a reduction (pure; no I/O)."""
    return {
        "target": target,
        "authorization": authorization,
        "mode": "local-static-candidate-hunt",
        "evidence_stage": "candidate",
        "tools": [{"tool": r.tool, "ran": r.ran, "count": len(r.findings), "error": r.error}
                  for r in results],
        "raw_candidate_count": len(rows),
        "funnel": reduction.funnel,
        "survivor_count": len(reduction.survivors),
        "families": [f.__dict__ for f in reduction.families],
        "survivors": [c.public() for c in reduction.survivors],
        "suppressed_summary": _reason_counts(reduction.suppressed),
        "note": ("Scanner observations are unverified candidates, not reproduced "
                 "vulnerabilities. Suppressed candidates are retained in aggregate with "
                 "reasons for audit. Promotion past 'candidate' requires the evidence "
                 "lifecycle (source-support, runtime, oracle, local reproduction, judge, "
                 "human review)."),
    }


def run_self_hunt(root: str = ".", *, target: str = "eliem08/aegis-openkritt",
                  out_dir: str = "reports/self_hunt", timeout: int = 600, on_event=None):
    """Scan a local checkout, reduce, and write ``<out_dir>/self_hunt.json``. Returns
    ``(report, reduction)``."""
    from .candidate_reduction import reduce_candidates
    from .tool_bridge import ToolBridge, available_tools

    tools = []
    for lane in _DEFAULT_LANES:
        tools.extend(available_tools(lane))
    tools = list({t.name: t for t in tools}.values())
    if not tools:
        raise SystemExit("no real scanners resolved on PATH — self-hunt cannot run")

    bridge = ToolBridge(timeout=timeout)
    results = bridge.scan(str(root), tools=tools, on_event=on_event)
    rows = bridge.findings(results)
    reduction = reduce_candidates(rows)

    report = build_report(target, "repository-owner self-audit (local checkout only)",
                          results, rows, reduction)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "self_hunt.json").write_text(json.dumps(report, indent=2, default=str),
                                        encoding="utf-8")
    return report, reduction


def main(argv=None) -> int:
    argv = list(argv or [])
    root = argv[0] if argv else os.environ.get("AEGIS_SELF_HUNT_ROOT", ".")
    report, reduction = run_self_hunt(root)
    ran = [t["tool"] for t in report["tools"] if t["ran"]]
    print("AEGIS SELF-HUNT — authorized local self-audit (candidates only)")
    print(f"  scanners: {', '.join(ran) or '(none resolved)'}")
    print("  FUNNEL:")
    for line in reduction.funnel_lines():
        print("  " + line)
    print(f"\n  {report['survivor_count']} candidate survivor(s) across "
          f"{len(reduction.families)} family(ies) from {report['raw_candidate_count']} "
          f"raw scanner observations.")
    for fam in reduction.families[:10]:
        print(f"    - {fam.cwe or fam.key} [{fam.path_class}] x{fam.count} "
              f"score={fam.score:.2f} tools={fam.tools} e.g. {fam.example_path}")
    print("  (Candidates are unverified hypotheses; none are reproduced vulnerabilities.)")
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv[1:]))
