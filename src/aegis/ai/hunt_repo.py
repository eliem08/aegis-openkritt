"""Autonomous Aegis-native repository hunt:

    python -m aegis.ai.hunt_repo <owner/repo> [--files N] [--subpath pkg/] [--no-validate]

Selects security-relevant files deterministically, analyzes each with DeepSeek,
pins the reviewed sources, then (by default) runs Aegis's own citation validator
over every hypothesis so confirmed/false-positive/unresolved verdicts come from
matching claims against the pinned source — not from model confidence.

Read-only: fetches public source, never executes it, never submits anything.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from ..env import load_dotenv
from .client import DeepSeekClient
from .config import DeepSeekConfig
from .github_source import GitHubRateLimitError, GitHubSource
from .repo_hunt import RepoHuntConfig, hunt_repository


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m aegis.ai.hunt_repo")
    parser.add_argument("repository", help="owner/repo, e.g. kubernetes/kubernetes")
    parser.add_argument("--files", type=int, default=12, help="files to analyze (default 12)")
    parser.add_argument("--subpath", default="", help="restrict to a subtree, e.g. pkg/")
    parser.add_argument("--no-validate", action="store_true", help="skip citation validation")
    args = parser.parse_args(list(argv) if argv is not None else None)

    load_dotenv()
    report_root = Path(os.environ.get("AEGIS_REPORT_DIR", "reports")).resolve()
    slug = args.repository.replace("/", "_")
    report_path = report_root / f"deepseek_{slug}.json"
    pin_dir = report_root / "repos" / args.repository.replace("/", "__")
    pin_dir.mkdir(parents=True, exist_ok=True)

    # Generation: no thinking traces, generous output budget for strict json.
    env = dict(os.environ)
    env.update(DEEPSEEK_THINKING="disabled", DEEPSEEK_TEMPERATURE="0.1",
               DEEPSEEK_MAX_TOKENS="16000", DEEPSEEK_READ_TIMEOUT="300")
    try:
        config = DeepSeekConfig.from_env(env)
    except Exception as exc:
        print(f"error: DeepSeek not configured ({type(exc).__name__})", file=sys.stderr)
        return 2

    def progress(index, total, path):
        print(f"  [{index}/{total}] {path}", flush=True)

    try:
        with GitHubSource(token=os.environ.get("GITHUB_TOKEN", "")) as source, \
                DeepSeekClient(config) as client:
            print(f"selecting files from {args.repository} ...", flush=True)
            result = hunt_repository(
                source, client, args.repository,
                config=RepoHuntConfig(max_files=args.files, subpath=args.subpath),
                pin_dir=pin_dir, progress=progress,
            )
    except GitHubRateLimitError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    report = result.report()
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nselected {len(result.selected)} files, "
          f"{len(result.hypotheses)} hypotheses -> {report_path.name}")
    for failure in result.failures:
        print(f"  ! {failure}")

    if args.no_validate or not result.hypotheses:
        return 0

    print("\nvalidating hypotheses against the pinned source ...", flush=True)
    from .report_validation import validate_deepseek_report

    validation_env = dict(env)
    validation_env.update(DEEPSEEK_MAX_TOKENS="4096")
    with DeepSeekClient(DeepSeekConfig.from_env(validation_env)) as client:
        validated, model = validate_deepseek_report(
            report_path, pin_dir, client,
            progress=lambda done, total, path: print(f"  [{done}/{total}] {path}", flush=True),
        )
    counts = validated["scan"]["validation_counts"]
    print(f"\nverdicts: {counts}")
    for item in model["items"]:
        if item["status"] == "confirmed":
            print(f"  CONFIRMED  {item['code_location']}  {item['observed'][:90]}")
    print(f"\nreview: http://127.0.0.1:8000/ui/deepseek/latest?repo_full={args.repository}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
