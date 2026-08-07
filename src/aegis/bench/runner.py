"""Aegis-Bench runner — measure bundled detector rules against a labeled corpus.

Writes vulnerable snippets into one temp tree and clean snippets into another, runs the
installed scanners over each via the real tool bridge, and scores per case:

  * detected (true positive) — a matching finding in the vulnerable file
  * missed (false negative) — no matching finding in the vulnerable file
  * false positive — a matching finding in the CLEAN file (negative control)

These are DETECTOR metrics only. A static scanner match never counts as a reproduced
vulnerability in Aegis's evidence lifecycle. ``as_benchmark_run()`` therefore carries the
detection counts into the canonical benchmark model while leaving ``reproduced=0``.

CI intentionally runs the canonical corpus with a pinned Semgrep version. A richer local
arsenal may contribute additional detectors when installed, but those tools are reported by
name and are not implied by the CI result. If no scanners are installed the run reports zero
tools and empty results; it never fabricates numbers.
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
        """Map detector metrics without falsely promoting detections to reproductions."""
        from aegis.benchmarking import BenchmarkRun

        return BenchmarkRun(
            benchmark="aegis-bench",
            detected=self.detected,
            reproduced=0,
            false_positives=self.false_positives,
            missed=self.missed,
        )

    def summary(self) -> dict:
        return {
            "tools": self.tools,
            "total": self.total,
            "detected": self.detected,
            "missed": self.missed,
            "false_positives": self.false_positives,
            "recall": self.recall,
            "precision": self.precision,
            "fp_rate": self.fp_rate,
            "cases": [asdict(c) for c in self.cases],
        }


def _ext(case: Case) -> str:
    return case.filename.rsplit(".", 1)[-1]


def _write_tree(cases, attr: str) -> Path:
    d = Path(tempfile.mkdtemp(prefix=f"aegis-bench-{attr}-"))
    for c in cases:
        (d / f"{c.id}.{_ext(c)}").write_text(getattr(c, attr), encoding="utf-8")
    return d


def _findings_by_file(scan_root: Path, tools) -> dict[str, list[dict]]:
    """basename -> normalized scanner findings for every result in ``scan_root``."""
    from aegis.ai.tool_bridge import ToolBridge

    results = ToolBridge(timeout=300).scan(str(scan_root), tools=tools)
    by_file: dict[str, list[dict]] = {}
    for result in results:
        for row in result.findings:
            answer = row.get("json_answer") or {}
            base = Path(str(answer.get("file_path") or "").replace("\\", "/")).name
            text = (
                str(answer.get("vulnerability_type") or "")
                + " "
                + str(answer.get("summary") or "")
                + " "
                + str(answer.get("explanation") or "")
            ).lower()
            by_file.setdefault(base, []).append({"tool": result.tool, "text": text})
    return by_file


def run_bench(cases=CASES) -> BenchResult:
    from aegis.ai.tool_bridge import available_tools

    # The corpus targets bundled Semgrep rules. Additional installed code/secrets scanners may
    # contribute observations locally, but CI's canonical lane intentionally pins Semgrep.
    tools = list({tool.name: tool for lane in ("code", "secrets")
                  for tool in available_tools(lane)}.values())
    if not tools:
        return BenchResult(
            tools=[],
            total=len(cases),
            detected=0,
            missed=len(cases),
            false_positives=0,
            cases=[CaseResult(case.id, case.cwe, False, False) for case in cases],
        )

    vuln_dir = _write_tree(cases, "vulnerable")
    clean_dir = _write_tree(cases, "clean")
    vuln_hits = _findings_by_file(vuln_dir, tools)
    clean_hits = _findings_by_file(clean_dir, tools)

    results: list[CaseResult] = []
    for case in cases:
        base = f"{case.id}.{_ext(case)}"
        vulnerable_matches = [f for f in vuln_hits.get(base, []) if case.match in f["text"]]
        clean_matches = [f for f in clean_hits.get(base, []) if case.match in f["text"]]
        results.append(
            CaseResult(
                id=case.id,
                cwe=case.cwe,
                detected=bool(vulnerable_matches),
                false_positive=bool(clean_matches),
                detectors=sorted({finding["tool"] for finding in vulnerable_matches}),
            )
        )
    detected = sum(1 for result in results if result.detected)
    false_positives = sum(1 for result in results if result.false_positive)
    return BenchResult(
        tools=[tool.name for tool in tools],
        total=len(cases),
        detected=detected,
        missed=len(cases) - detected,
        false_positives=false_positives,
        cases=results,
    )


def main(argv=None) -> int:
    res = run_bench()
    print(f"\nAEGIS-BENCH — detectors: {', '.join(res.tools) or '(none installed)'}")
    print("-" * 72)
    for case in res.cases:
        mark = "✓ DETECT" if case.detected else "✗ MISS  "
        fp = "  ⚠ FP-on-clean" if case.false_positive else ""
        print(f"  {mark}  {case.cwe:9} {case.id:28} {','.join(case.detectors)}{fp}")
    print("-" * 72)
    print(
        f"  cases {res.total} | detected {res.detected} | missed {res.missed} | "
        f"false-positives {res.false_positives}"
    )
    print(
        f"  recall {res.recall:.2f} | precision {res.precision:.2f} | "
        f"fp_rate {res.fp_rate:.2f}"
    )
    if not res.tools:
        print("  (no scanners installed — run inside the scanner environment for real numbers)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
