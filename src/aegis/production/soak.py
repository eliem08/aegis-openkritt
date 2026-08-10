"""Timed production-runtime soak runner for the existing durability scenario suite."""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence

CI_MIN_SECONDS = 600
OPERATOR_MIN_SECONDS = 21_600
DAY_MIN_SECONDS = 86_400


@dataclass(frozen=True, slots=True)
class SoakReport:
    requested_seconds: int
    elapsed_seconds: float
    cycles_completed: int
    failed_cycle: int | None
    status: str
    command: tuple[str, ...]
    mode: str = "ci"
    started_at: str = ""
    checkpoint_sequence: int = 0
    failure_timeline: tuple[dict, ...] = ()


def run_soak(
    command: Sequence[str],
    *,
    duration_seconds: int,
    operator_mode: bool = False,
    soak_mode: str | None = None,
    allow_short: bool = False,
    runner: Callable[[Sequence[str]], int] | None = None,
    clock: Callable[[], float] = time.monotonic,
    checkpoint: Callable[[SoakReport], None] | None = None,
    resume_from: SoakReport | None = None,
) -> SoakReport:
    mode = soak_mode or ("six-hour" if operator_mode else "ci")
    if mode not in {"ci", "six-hour", "24-hour"}:
        raise ValueError("soak mode must be ci, six-hour, or 24-hour")
    minimum = {
        "ci": CI_MIN_SECONDS, "six-hour": OPERATOR_MIN_SECONDS, "24-hour": DAY_MIN_SECONDS,
    }[mode]
    if not allow_short and duration_seconds < minimum:
        raise ValueError(f"soak duration must be at least {minimum} seconds")
    if duration_seconds <= 0 or not command:
        raise ValueError("soak requires a positive duration and command")
    execute = runner or (lambda argv: subprocess.run(argv, check=False).returncode)
    started = clock()
    cycles = resume_from.cycles_completed if resume_from else 0
    prior_elapsed = resume_from.elapsed_seconds if resume_from else 0.0
    started_at = resume_from.started_at if resume_from else datetime.now(timezone.utc).isoformat()
    checkpoint_sequence = resume_from.checkpoint_sequence if resume_from else 0
    failure_timeline = list(resume_from.failure_timeline if resume_from else ())
    failed_cycle = None
    while clock() - started < duration_seconds:
        code = execute(tuple(command))
        if code != 0:
            failed_cycle = cycles + 1
            failure_timeline.append({"cycle": failed_cycle, "kind": "cycle_failed", "exit_code": code})
            break
        cycles += 1
        checkpoint_sequence += 1
        if checkpoint is not None:
            checkpoint(SoakReport(
                duration_seconds, prior_elapsed + max(0.0, clock() - started), cycles,
                None, "running", tuple(command), mode, started_at,
                checkpoint_sequence, tuple(failure_timeline),
            ))
    elapsed = max(0.0, clock() - started)
    return SoakReport(
        requested_seconds=duration_seconds,
        elapsed_seconds=prior_elapsed + elapsed,
        cycles_completed=cycles,
        failed_cycle=failed_cycle,
        status="pass" if failed_cycle is None and cycles > 0 else "fail",
        command=tuple(command),
        mode=mode,
        started_at=started_at,
        checkpoint_sequence=checkpoint_sequence,
        failure_timeline=tuple(failure_timeline),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration-seconds", type=int, default=CI_MIN_SECONDS)
    parser.add_argument("--operator", action="store_true")
    parser.add_argument("--mode", choices=("ci", "six-hour", "24-hour"))
    parser.add_argument("--report", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    report = run_soak(
        command,
        duration_seconds=args.duration_seconds,
        operator_mode=args.operator,
        soak_mode="six-hour" if args.operator and args.mode in {None, "ci"} else args.mode,
    )
    Path(args.report).write_text(
        json.dumps(asdict(report), indent=2) + "\n", encoding="utf-8"
    )
    return 0 if report.status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
