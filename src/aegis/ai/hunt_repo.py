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
from .repo_clone import LocalRepoSource, RepoCloneError, clone_repository
from .repo_hunt import RepoHuntConfig, hunt_repository


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m aegis.ai.hunt_repo")
    parser.add_argument("repository", help="owner/repo, e.g. kubernetes/kubernetes")
    parser.add_argument("--files", type=int, default=12, help="files to analyze (default 12)")
    parser.add_argument("--subpath", default="", help="restrict to a subtree, e.g. pkg/")
    parser.add_argument("--no-validate", action="store_true", help="skip citation validation")
    parser.add_argument("--api", action="store_true",
                        help="read via the GitHub API instead of cloning (rate-limited)")
    parser.add_argument("--refresh", action="store_true", help="update an existing clone")
    parser.add_argument("--handle", default="",
                        help="HackerOne program handle, recorded with outcomes and PoCs")
    parser.add_argument("--since-days", type=int, default=0,
                        help="only analyze source files changed in the last N days "
                             "(the 'recently shipped' edge); 0 = whole repo")
    parser.add_argument("--hint", default="",
                        help="operator lead to seed the hunt, e.g. 'YAML deserialized from a "
                             "member-role user in the GraphQL import endpoint'")
    parser.add_argument("--samples", type=int, default=1,
                        help="generator ensemble: analyze each file N times over a "
                             "temperature spread and union findings (higher recall, N× cost)")
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

    token = os.environ.get("GITHUB_TOKEN", "")

    # the "recently shipped" edge: restrict analysis to source files changed in the
    # last N days (needs the GitHub API for the commit history)
    include_paths: frozenset = frozenset()
    if args.since_days > 0:
        from .fresh_commits import recent_source_files
        import httpx as _httpx
        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        with _httpx.Client(headers=headers) as gh:
            changed = recent_source_files(args.repository, gh_client=gh, days=args.since_days)
        include_paths = frozenset(changed)
        print(f"recently-shipped filter: {len(include_paths)} source files changed in "
              f"the last {args.since_days}d", flush=True)
        if not include_paths:
            print("  nothing changed in that window; exiting", flush=True)
            return 0

    changed_ranges: dict = {}
    try:
        if args.api:
            source_cm = GitHubSource(token=token)
            # API reads cost rate limit, so only a sampled pool can be content-scanned
            hunt_config = RepoHuntConfig(max_files=args.files, subpath=args.subpath, include_paths=include_paths, samples=args.samples, operator_hint=args.hint)
        else:
            print(f"cloning {args.repository} ...", flush=True)
            clone = clone_repository(
                args.repository,
                cache_dir=os.environ.get("AEGIS_CLONE_DIR") or report_root / "clones",
                refresh=args.refresh, token=token,
            )
            print(f"  {'reused' if clone.reused else 'cloned'} {clone.path} @ "
                  f"{clone.commit[:12]}", flush=True)
            source_cm = LocalRepoSource(clone.path, clone.commit)
            # diff-scoped focus: tell the generator which lines just changed
            if include_paths:
                from .fresh_commits import changed_line_ranges
                changed_ranges = {p: changed_line_ranges(clone.path, p) for p in include_paths}
                changed_ranges = {p: r for p, r in changed_ranges.items() if r}
            # local reads are ~free: content-scan a broad slice of the tree rather
            # than the small sampled pool an API budget forces (bounded so a
            # 20k-file monorepo still finishes quickly)
            hunt_config = RepoHuntConfig(max_files=args.files, subpath=args.subpath,
                                         content_scan_pool=3000, include_paths=include_paths, samples=args.samples, changed_ranges=changed_ranges, operator_hint=args.hint)
        with source_cm as source, DeepSeekClient(config) as client:
            print(f"selecting files from {args.repository} ...", flush=True)
            result = hunt_repository(
                source, client, args.repository,
                config=hunt_config, pin_dir=pin_dir, progress=progress,
            )
    except GitHubRateLimitError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except RepoCloneError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4

    report = result.report()

    # arm's-length: invoke the operator's installed skills (AEGIS_SKILL_CMD) on this repo
    # and fold their output into the report as unverified candidates — same boundary as
    # the open-kritt bridge, no skill source embedded.
    from .skill_bridge import SkillBridge
    bridge = SkillBridge()
    if bridge.enabled:
        print("\ninvoking installed skills (arm's-length) ...", flush=True)
        runs = bridge.run(args.repository, target_kind="repo")
        for r in runs:
            print(f"  [{'ok' if r.ok else 'fail'}] {r.skill}" + (f" — {r.error}" if r.error else ""))
        skill_rows = bridge.to_findings(runs, repository=args.repository)
        if skill_rows:
            report.setdefault("vulnerabilities", []).extend(skill_rows)
            print(f"  folded {len(skill_rows)} skill candidate(s) into the report")

    # run any installed OSS scanners (semgrep/gitleaks/bandit/njsscan/trivy) on the
    # clone and fold their deterministic findings in — unless --api (no local checkout)
    if not args.api:
        from .tool_bridge import ToolBridge, available_tools
        avail = available_tools("code") + available_tools("secrets") + available_tools("deps")
        if avail:
            names = ", ".join(sorted({t.name for t in avail}))
            print(f"\nrunning installed scanners ({names}) ...", flush=True)
            tresults = ToolBridge().scan(str(pin_dir), tools=list({t.name: t for t in avail}.values()))
            for tr in tresults:
                print(f"  [{'ok' if tr.ran else 'fail'}] {tr.tool}: {len(tr.findings)} finding(s)"
                      + (f" — {tr.error}" if tr.error else ""))
            tool_rows = ToolBridge().findings(tresults)
            if tool_rows:
                report.setdefault("vulnerabilities", []).extend(tool_rows)
                print(f"  folded {len(tool_rows)} scanner finding(s) into the report")

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

    # feed every verdict back into the learning store, so recurring false-positive
    # shapes and true detections both inform future calibration
    _record_outcomes(validated, program_handle=args.handle)

    # scaffold a human-runnable PoC for each confirmed finding — the only path from
    # "candidate" to a submittable report these programs will accept
    if counts.get("confirmed"):
        from .poc_harness import build_pocs_from_report
        poc_root = report_root / "poc" / args.repository.replace("/", "__")
        clone_root = None if args.api else pin_dir
        arts = build_pocs_from_report(
            report_path, poc_root, program_handle=args.handle,
            repo_root=clone_root,
        )
        print(f"\nscaffolded {len(arts)} PoC(s) under {poc_root} — each needs a human "
              "to reproduce on a running instance before submission")

    print(f"\nreview: http://127.0.0.1:8000/ui/deepseek/latest?repo_full={args.repository}")
    return 0


def _record_outcomes(validated: dict, *, program_handle: str = "") -> None:
    """Persist each verdict to the learning store (best-effort; never fails the hunt)."""
    try:
        from ..learn.store import Outcome, OutcomeStore, Verdict
    except Exception:
        return
    _map = {"confirmed": Verdict.CONFIRMED, "false_positive": Verdict.FALSE_POSITIVE,
            "unresolved": Verdict.PENDING}
    scan = validated.get("scan") or {}
    repo = scan.get("repository", "")
    try:
        store = OutcomeStore(os.environ.get("AEGIS_LEARN_DB") or "aegis-learn.db")
    except Exception:
        return
    from .agents.runner import cwe_key
    for row in validated.get("vulnerabilities") or []:
        answer = row.get("json_answer") or {}
        verdict = (row.get("validation") or {}).get("verdict", "unresolved")
        try:
            store.record(Outcome(
                detector="ai:repo-hunt",
                cwe=cwe_key(answer.get("vulnerability_type") or "")[:80],
                verdict=_map.get(verdict, Verdict.PENDING),
                fingerprint=str(row.get("target") or answer.get("file_path") or "")[:200],
                asset=repo,
                program=program_handle,
                summary=str(answer.get("summary") or "")[:200],
            ))
        except Exception:
            continue


if __name__ == "__main__":
    raise SystemExit(main())
