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
