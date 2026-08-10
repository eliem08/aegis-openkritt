"""Whole-repository CVE discovery recall, separate from path-hinted ground truth."""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

from .real_cve import (
    RealCase,
    RealCaseResult,
    _configured_cases,
    _whole_repository_survivors,
    run_real_case,
)


@dataclass(frozen=True)
class WholeRepositoryResult:
    cases: tuple[RealCaseResult, ...]

    def summary(self) -> dict:
        scored_statuses = {"detected", "detector_missed", "discovery_missed", "regressed"}
        scored = [case for case in self.cases if case.status in scored_statuses]
        detected = sum(case.status == "detected" for case in scored)
        return {
            "metric": "whole_repository_discovery_recall",
            "total": len(self.cases),
            "scored": len(scored),
            "detected": detected,
            "whole_repository_discovery_recall": round(detected / len(scored), 4) if scored else 0.0,
            "detector_misses": sum(case.status == "detector_missed" for case in scored),
            "discovery_misses": sum(case.status == "discovery_missed" for case in scored),
            "regressions": sum(case.status == "regressed" for case in scored),
            "by_status": dict(Counter(case.status for case in self.cases)),
        }


def run_whole_repository_bench(
    cases: tuple[RealCase, ...] | None = None,
) -> WholeRepositoryResult:
    selected = cases if cases is not None else _configured_cases()
    return WholeRepositoryResult(tuple(
        run_real_case(
            case, scanner=_whole_repository_survivors, whole_repository=True,
        ) for case in selected
    ))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", dest="json_path")
    args = parser.parse_args(argv)
    result = run_whole_repository_bench()
    summary = result.summary()
    document = {
        "metric": "whole_repository_discovery_recall",
        "path_hinted_ground_truth_recall": None,
        "summary": summary,
        "cases": [asdict(case) for case in result.cases],
    }
    print("AEGIS WHOLE-REPOSITORY CVE DISCOVERY")
    print(json.dumps(summary, sort_keys=True))
    if args.json_path:
        Path(args.json_path).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    strict = os.environ.get("AEGIS_WHOLE_REPO_CVE_STRICT", "").lower() in {"1", "true", "yes"}
    return 1 if strict and (not summary["scored"] or summary["regressions"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
