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
    target_seconds: int = 0


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
    target_seconds: int | None = None,
) -> SoakReport:
    mode = soak_mode or ("six-hour" if operator_mode else "ci")
    if mode not in {"ci", "six-hour", "24-hour"}:
        raise ValueError("soak mode must be ci, six-hour, or 24-hour")
    minimum = {
        "ci": CI_MIN_SECONDS, "six-hour": OPERATOR_MIN_SECONDS, "24-hour": DAY_MIN_SECONDS,
    }[mode]
    target = target_seconds or duration_seconds
    if target < duration_seconds:
        raise ValueError("soak target cannot be shorter than its segment")
    if resume_from and resume_from.target_seconds not in {0, target}:
        raise ValueError("resume target does not match the persisted soak target")
    if not allow_short and target < minimum:
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
                target,
            ))
    elapsed = max(0.0, clock() - started)
    return SoakReport(
        requested_seconds=duration_seconds,
        elapsed_seconds=prior_elapsed + elapsed,
        cycles_completed=cycles,
        failed_cycle=failed_cycle,
        status=(
            "fail" if failed_cycle is not None or cycles <= 0 else
            "pass" if prior_elapsed + elapsed >= target else "partial"
        ),
        command=tuple(command),
        mode=mode,
        started_at=started_at,
        checkpoint_sequence=checkpoint_sequence,
        failure_timeline=tuple(failure_timeline),
        target_seconds=target,
    )


def _write_report(path: Path, report: SoakReport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(asdict(report), indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def _load_report(path: Path) -> SoakReport:
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["command"] = tuple(payload.get("command", ()))
    payload["failure_timeline"] = tuple(payload.get("failure_timeline", ()))
    return SoakReport(**payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration-seconds", type=int, default=CI_MIN_SECONDS)
    parser.add_argument("--operator", action="store_true")
    parser.add_argument("--mode", choices=("ci", "six-hour", "24-hour"))
    parser.add_argument("--report", required=True)
    parser.add_argument("--resume-report")
    parser.add_argument("--target-seconds", type=int)
    parser.add_argument("--allow-short-segment", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    report_path = Path(args.report)
    resume = _load_report(Path(args.resume_report)) if args.resume_report else None
    report = run_soak(
        command,
        duration_seconds=args.duration_seconds,
        operator_mode=args.operator,
        soak_mode="six-hour" if args.operator and args.mode in {None, "ci"} else args.mode,
        allow_short=args.allow_short_segment,
        checkpoint=lambda current: _write_report(report_path, current),
        resume_from=resume,
        target_seconds=args.target_seconds,
    )
    _write_report(report_path, report)
    return 0 if report.status in {"pass", "partial"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
