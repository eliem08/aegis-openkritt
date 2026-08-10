"""Timed production-runtime soak runner for the existing durability scenario suite."""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Sequence

CI_MIN_SECONDS = 600
OPERATOR_MIN_SECONDS = 21_600


@dataclass(frozen=True, slots=True)
class SoakReport:
    requested_seconds: int
    elapsed_seconds: float
    cycles_completed: int
    failed_cycle: int | None
    status: str
    command: tuple[str, ...]


def run_soak(
    command: Sequence[str],
    *,
    duration_seconds: int,
    operator_mode: bool = False,
    allow_short: bool = False,
    runner: Callable[[Sequence[str]], int] | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> SoakReport:
    minimum = OPERATOR_MIN_SECONDS if operator_mode else CI_MIN_SECONDS
    if not allow_short and duration_seconds < minimum:
        raise ValueError(f"soak duration must be at least {minimum} seconds")
    if duration_seconds <= 0 or not command:
        raise ValueError("soak requires a positive duration and command")
    execute = runner or (lambda argv: subprocess.run(argv, check=False).returncode)
    started = clock()
    cycles = 0
    failed_cycle = None
    while clock() - started < duration_seconds:
        code = execute(tuple(command))
        if code != 0:
            failed_cycle = cycles + 1
            break
        cycles += 1
    elapsed = max(0.0, clock() - started)
    return SoakReport(
        requested_seconds=duration_seconds,
        elapsed_seconds=elapsed,
        cycles_completed=cycles,
        failed_cycle=failed_cycle,
        status="pass" if failed_cycle is None and cycles > 0 else "fail",
        command=tuple(command),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration-seconds", type=int, default=CI_MIN_SECONDS)
    parser.add_argument("--operator", action="store_true")
    parser.add_argument("--report", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    report = run_soak(
        command,
        duration_seconds=args.duration_seconds,
        operator_mode=args.operator,
    )
    Path(args.report).write_text(
        json.dumps(asdict(report), indent=2) + "\n", encoding="utf-8"
    )
    return 0 if report.status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
