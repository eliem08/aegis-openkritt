"""Aegis-Bench: metric math, corpus integrity, and scanner-gated regression tests."""

from __future__ import annotations

import os

import pytest

from aegis.bench import CASES, run_bench
from aegis.bench.runner import BenchResult, CaseResult


def _res(detected, fps, total):
    cases = (
        [CaseResult(f"d{i}", "CWE-1", True, False) for i in range(detected)]
        + [CaseResult(f"m{i}", "CWE-1", False, False) for i in range(total - detected)]
    )
    return BenchResult(
        tools=["semgrep"],
        total=total,
        detected=detected,
        missed=total - detected,
        false_positives=fps,
        cases=cases,
    )


def test_metric_math():
    result = _res(detected=8, fps=1, total=10)
    assert result.recall == 0.8
    assert result.precision == round(8 / 9, 4)
    assert result.fp_rate == 0.1


def test_metric_math_zero_safe():
    result = BenchResult(tools=[], total=0, detected=0, missed=0, false_positives=0)
    assert result.recall == 0.0
    assert result.precision == 0.0
    assert result.fp_rate == 0.0


def test_as_benchmark_run_keeps_detection_separate_from_reproduction():
    run = _res(detected=7, fps=2, total=10).as_benchmark_run()
    assert run.benchmark == "aegis-bench"
    assert run.detected == 7
    assert run.missed == 3
    assert run.reproduced == 0
    assert run.reproduction_rate == 0.0
    assert run.detector_precision == pytest.approx(7 / 9)
    assert run.detector_recall == pytest.approx(0.7)
    # Generic evidence precision intentionally remains zero until actual reproduction occurs.
    assert run.precision == 0.0


def test_corpus_integrity():
    ids = [case.id for case in CASES]
    assert len(ids) == len(set(ids))
    assert len(CASES) >= 8
    for case in CASES:
        assert case.vulnerable and case.clean and case.match
        assert case.match == case.match.lower()
        assert "." in case.filename
        assert case.vulnerable != case.clean


def test_run_bench_returns_full_result():
    result = run_bench()
    assert result.total == len(CASES)
    assert len(result.cases) == len(CASES)
    assert result.detected + result.missed == result.total


@pytest.mark.skipif(
    os.environ.get("AEGIS_BENCH_STRICT", "").strip().lower() not in ("1", "true", "yes"),
    reason=(
        "canonical detector regression runs only where the pinned scanner truly works "
        "(AEGIS_BENCH_STRICT=1, e.g. Linux CI)"
    ),
)
def test_canonical_detector_regression_is_perfect_when_strict():
    """Our self-authored canonical pairs are a zero-regression gate, not a field benchmark."""
    result = run_bench()
    assert result.tools, "strict benchmark requires at least one functioning scanner"
    assert result.detected == result.total, f"canonical detection regression: {result.summary()}"
    assert result.false_positives == 0, f"clean-twin regression: {result.summary()}"
    assert result.recall == 1.0
    assert result.fp_rate == 0.0
