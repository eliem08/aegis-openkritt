from __future__ import annotations

import pytest

from aegis.production.soak import run_soak


class Clock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        self.value += 0.05
        return self.value


def test_soak_repeats_green_scenarios_and_fails_on_first_bad_cycle():
    clock = Clock()
    passing = run_soak(
        ("pytest", "durability"), duration_seconds=1, allow_short=True,
        runner=lambda _command: 0, clock=clock,
    )
    assert passing.status == "pass" and passing.cycles_completed > 1

    calls = []
    clock = Clock()

    def fail_second(_command):
        calls.append(1)
        return 1 if len(calls) == 2 else 0

    failed = run_soak(
        ("pytest", "durability"), duration_seconds=1, allow_short=True,
        runner=fail_second, clock=clock,
    )
    assert failed.status == "fail" and failed.failed_cycle == 2


def test_soak_enforces_ci_and_operator_minimums():
    with pytest.raises(ValueError, match="600"):
        run_soak(("pytest",), duration_seconds=599, runner=lambda _command: 0)
    with pytest.raises(ValueError, match="21600"):
        run_soak(
            ("pytest",), duration_seconds=600, operator_mode=True,
            runner=lambda _command: 0,
        )
    with pytest.raises(ValueError, match="86400"):
        run_soak(("pytest",), duration_seconds=21_600, soak_mode="24-hour", runner=lambda _: 0)


def test_soak_checkpoints_and_resumes_without_resetting_cycle_identity():
    reports = []
    first = run_soak(
        ("worker",), duration_seconds=1, soak_mode="six-hour", allow_short=True,
        runner=lambda _: 0, clock=Clock(), checkpoint=reports.append,
    )
    resumed = run_soak(
        ("worker",), duration_seconds=1, soak_mode="six-hour", allow_short=True,
        runner=lambda _: 0, clock=Clock(), resume_from=first,
    )
    assert reports and reports[-1].status == "running"
    assert resumed.cycles_completed > first.cycles_completed
    assert resumed.checkpoint_sequence > first.checkpoint_sequence
    assert resumed.started_at == first.started_at


def test_segmented_soak_accumulates_real_elapsed_to_one_target():
    first = run_soak(
        ("worker",), duration_seconds=1, soak_mode="six-hour", allow_short=True,
        runner=lambda _: 0, clock=Clock(), target_seconds=2,
    )
    assert first.status == "partial" and first.target_seconds == 2
    resumed = run_soak(
        ("worker",), duration_seconds=1, soak_mode="six-hour", allow_short=True,
        runner=lambda _: 0, clock=Clock(), resume_from=first, target_seconds=2,
    )
    assert resumed.status == "pass"
    assert resumed.elapsed_seconds >= 2


def test_segmented_soak_rejects_target_change_on_resume():
    first = run_soak(
        ("worker",), duration_seconds=1, allow_short=True,
        runner=lambda _: 0, clock=Clock(), target_seconds=2,
    )
    with pytest.raises(ValueError, match="resume target"):
        run_soak(
            ("worker",), duration_seconds=1, allow_short=True,
            runner=lambda _: 0, clock=Clock(), resume_from=first, target_seconds=3,
        )
