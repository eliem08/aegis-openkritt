"""Aegis-Bench: metric math (deterministic), corpus integrity, and a scanner-gated real run."""

from __future__ import annotations

import os

import pytest

from aegis.bench import CASES, run_bench
from aegis.bench.runner import BenchResult, CaseResult


def _res(detected, fps, total):
    cases = ([CaseResult(f"d{i}", "CWE-1", True, False) for i in range(detected)]
             + [CaseResult(f"m{i}", "CWE-1", False, False) for i in range(total - detected)])
    return BenchResult(tools=["semgrep"], total=total, detected=detected,
                       missed=total - detected, false_positives=fps, cases=cases)


def test_metric_math():
    r = _res(detected=8, fps=1, total=10)
    assert r.recall == 0.8
    assert r.precision == round(8 / 9, 4)     # tp / (tp + fp)
    assert r.fp_rate == 0.1


def test_metric_math_zero_safe():
    r = BenchResult(tools=[], total=0, detected=0, missed=0, false_positives=0)
    assert r.recall == 0.0 and r.precision == 0.0 and r.fp_rate == 0.0


def test_as_benchmark_run_maps_and_validates():
    run = _res(detected=7, fps=2, total=10).as_benchmark_run()
    assert run.benchmark == "aegis-bench" and run.detected == 7
    assert run.reproduced == 7 and run.false_positives == 2
    assert 0.0 <= run.precision <= 1.0


def test_corpus_integrity():
    ids = [c.id for c in CASES]
    assert len(ids) == len(set(ids)) and len(CASES) >= 8
    for c in CASES:
        assert c.vulnerable and c.clean and c.match
        assert c.match == c.match.lower()
        assert "." in c.filename
        assert c.vulnerable != c.clean


def test_run_bench_returns_full_result():
    res = run_bench()
    assert res.total == len(CASES)
    assert len(res.cases) == len(CASES)
    assert res.detected + res.missed == res.total


@pytest.mark.skipif(
    os.environ.get("AEGIS_BENCH_STRICT", "").strip().lower() not in ("1", "true", "yes"),
    reason="detector-signal gate runs only where scanners truly work (AEGIS_BENCH_STRICT=1, "
           "e.g. the arsenal image / CI) — resolving a binary != it functioning (semgrep-core "
           "does not run on Windows).")
def test_detectors_have_signal_when_strict():
    # where scanners genuinely function, our own bundled rules should catch the majority of
    # the corpus (these cases target those exact rules) and stay clean on the negative controls.
    res = run_bench()
    assert res.recall >= 0.6, f"recall too low: {res.summary()}"
    assert res.fp_rate <= 0.2, f"too many false positives: {res.summary()}"
