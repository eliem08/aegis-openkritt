"""Aegis-Bench runner — measure the bundled detectors against the labeled corpus.

Writes the vulnerable snippets into one temp tree and the clean snippets into another, runs
the installed scanners over each (via the tool bridge), and scores per case:

  * detected (true positive)  — a matching finding in the vulnerable file
  * missed  (false negative)  — no matching finding in the vulnerable file
  * false positive           — a matching finding in the CLEAN file (negative control)

Metrics (recall, precision, FP rate) are MEASURED from real scanner output, and also folded
into :class:`aegis.benchmarking.BenchmarkRun` so the existing release gate can consume them.
If no scanners are installed the run reports zero tools and empty results (callers skip the
scanner-dependent assertions) — it never fabricates numbers.
"""

from __future__ import annotations

import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .corpus import CASES, Case


@dataclass
class CaseResult:
    id: str
    cwe: str
    detected: bool          # vulnerable snippet flagged (true positive)
    false_positive: bool    # clean snippet flagged (negative control failed)
    detectors: list[str] = field(default_factory=list)


@dataclass
class BenchResult:
    tools: list[str]
    total: int
    detected: int
    missed: int
    false_positives: int
    cases: list[CaseResult] = field(default_factory=list)

    @property
    def recall(self) -> float:
        return round(self.detected / self.total, 4) if self.total else 0.0

    @property
    def precision(self) -> float:
        tp_fp = self.detected + self.false_positives
        return round(self.detected / tp_fp, 4) if tp_fp else 0.0

    @property
    def fp_rate(self) -> float:
        return round(self.false_positives / self.total, 4) if self.total else 0.0

    def as_benchmark_run(self):
        from aegis.benchmarking import BenchmarkRun
        # static-detection: a deterministic corpus match is the "reproduction" of the finding.
        return BenchmarkRun(benchmark="aegis-bench", detected=self.detected,
                            reproduced=self.detected, false_positives=self.false_positives)

    def summary(self) -> dict:
        return {"tools": self.tools, "total": self.total, "detected": self.detected,
                "missed": self.missed, "false_positives": self.false_positives,
                "recall": self.recall, "precision": self.precision, "fp_rate": self.fp_rate,
                "cases": [asdict(c) for c in self.cases]}


def _ext(case: Case) -> str:
    return case.filename.rsplit(".", 1)[-1]


def _write_tree(cases, attr: str) -> Path:
    d = Path(tempfile.mkdtemp(prefix=f"aegis-bench-{attr}-"))
    for c in cases:
        (d / f"{c.id}.{_ext(c)}").write_text(getattr(c, attr), encoding="utf-8")
    return d


def _findings_by_file(scan_root: Path, tools) -> dict[str, list[dict]]:
    """basename -> list of (cwe, message) for every scanner finding in scan_root."""
    from aegis.ai.tool_bridge import ToolBridge
    results = ToolBridge(timeout=300).scan(str(scan_root), tools=tools)
    by_file: dict[str, list[dict]] = {}
    for r in results:
        for row in r.findings:
            a = row.get("json_answer") or {}
            base = Path(str(a.get("file_path") or "").replace("\\", "/")).name
            text = (str(a.get("vulnerability_type") or "") + " "
                    + str(a.get("summary") or "") + " " + str(a.get("explanation") or "")).lower()
            by_file.setdefault(base, []).append({"tool": r.tool, "text": text})
    return by_file


def run_bench(cases=CASES) -> BenchResult:
    from aegis.ai.tool_bridge import available_tools
    # code + secrets lanes cover our bundled rules (semgrep) + gitleaks/detect-secrets.
    tools = list({t.name: t for ln in ("code", "secrets") for t in available_tools(ln)}.values())
    if not tools:
        return BenchResult(tools=[], total=len(cases), detected=0, missed=len(cases),
                           false_positives=0,
                           cases=[CaseResult(c.id, c.cwe, False, False) for c in cases])

    vuln_dir = _write_tree(cases, "vulnerable")
    clean_dir = _write_tree(cases, "clean")
    vuln_hits = _findings_by_file(vuln_dir, tools)
    clean_hits = _findings_by_file(clean_dir, tools)

    results: list[CaseResult] = []
    for c in cases:
        base = f"{c.id}.{_ext(c)}"
        vmatch = [f for f in vuln_hits.get(base, []) if c.match in f["text"]]
        cmatch = [f for f in clean_hits.get(base, []) if c.match in f["text"]]
        results.append(CaseResult(id=c.id, cwe=c.cwe, detected=bool(vmatch),
                                  false_positive=bool(cmatch),
                                  detectors=sorted({f["tool"] for f in vmatch})))
    detected = sum(1 for r in results if r.detected)
    fps = sum(1 for r in results if r.false_positive)
    return BenchResult(tools=[t.name for t in tools], total=len(cases), detected=detected,
                       missed=len(cases) - detected, false_positives=fps, cases=results)


def main(argv=None) -> int:
    res = run_bench()
    print(f"\nAEGIS-BENCH — detectors: {', '.join(res.tools) or '(none installed)'}")
    print("-" * 72)
    for c in res.cases:
        mark = "✓ DETECT" if c.detected else "✗ MISS  "
        fp = "  ⚠ FP-on-clean" if c.false_positive else ""
        print(f"  {mark}  {c.cwe:9} {c.id:28} {','.join(c.detectors)}{fp}")
    print("-" * 72)
    print(f"  cases {res.total} | detected {res.detected} | missed {res.missed} | "
          f"false-positives {res.false_positives}")
    print(f"  recall {res.recall:.2f} | precision {res.precision:.2f} | fp_rate {res.fp_rate:.2f}")
    if not res.tools:
        print("  (no scanners installed — run inside the arsenal image for real numbers)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
