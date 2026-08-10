"""Real-CVE detector ground truth — measure the bundled detectors on code Aegis did NOT author.

The synthetic corpus (:mod:`aegis.bench.corpus`) proves the rules recognize canonical patterns.
This lane is the harder, honest question the reviews asked for: on *real third-party projects*,
do the detectors catch a genuine historical vulnerability and stay clean on its fix?

To avoid fabricated commit SHAs, each case is **self-verifying**: it names a repository and a
literal code ``pattern`` that a real fix removed. The runner clones the repo and derives the
(vulnerable, fixed) commit pair from the repo's OWN history via ``git log -S`` (pickaxe) — the
commit whose diff *removes* the pattern is the fix, its parent is the vulnerable revision. It then
runs the real scanners + reduction funnel over both revisions and scores:

    detected  — a matching survivor at the vulnerable revision (true positive)
    regressed — a matching survivor still present at the fixed revision (false positive on the fix)

Numbers are MEASURED, never asserted. If a case's pair cannot be derived (pattern/fix not found)
or no scanners are installed, the case is reported ``skipped`` rather than counted — the corpus
never inflates recall.
"""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class RealCase:
    id: str
    repo: str                 # clone URL or owner/repo (github assumed if no scheme)
    pattern: str              # literal code the FIX removed (git -S pickaxe target)
    cwe: str                  # expected weakness class
    path_hint: str = ""       # optional path substring to disambiguate the vulnerable file
    match: str = ""           # lowercase substring expected in a finding (defaults to cwe)
    cve: str = ""             # public CVE identifier (GHSA-only cases may leave this blank)
    advisory_url: str = ""    # authoritative advisory used to establish ground truth
    expected_fix_commit: str = ""  # immutable upstream fix identity; derivation must agree
    required_tools: tuple[str, ...] = ()  # detector backends capable of scoring this case

    def expected(self) -> str:
        return (self.match or self.cwe).lower()


@dataclass
class RealCaseResult:
    id: str
    status: str               # detected | missed | regressed | unavailable | invalid | skipped
    reason: str = ""
    vulnerable_ref: str = ""
    fixed_ref: str = ""
    detectors: list[str] = field(default_factory=list)


@dataclass
class RealBenchResult:
    cases: list[RealCaseResult] = field(default_factory=list)

    @property
    def scored(self) -> list[RealCaseResult]:
        return [c for c in self.cases if c.status in ("detected", "missed", "regressed")]

    @property
    def recall(self) -> float:
        scored = self.scored
        if not scored:
            return 0.0
        return round(sum(1 for c in scored if c.status == "detected") / len(scored), 4)

    @property
    def regressions(self) -> int:
        return sum(1 for c in self.cases if c.status == "regressed")

    @property
    def unavailable(self) -> int:
        return sum(1 for c in self.cases if c.status == "unavailable")

    @property
    def invalid(self) -> int:
        return sum(1 for c in self.cases if c.status == "invalid")

    @property
    def measured(self) -> bool:
        """True only when at least one case reached a functioning detector."""
        return bool(self.scored)

    def summary(self) -> dict:
        from collections import Counter
        return {"total": len(self.cases), "scored": len(self.scored),
                "recall": self.recall, "regressions": self.regressions,
                "unavailable": self.unavailable, "invalid": self.invalid,
                "measured": self.measured,
                "by_status": dict(Counter(c.status for c in self.cases))}


@dataclass
class ScanObservation:
    detectors: list[str] = field(default_factory=list)
    attempted: list[str] = field(default_factory=list)
    unavailable: dict[str, str] = field(default_factory=dict)

    @property
    def any_ran(self) -> bool:
        return bool(self.attempted)

    def can_score(self, required_tools: tuple[str, ...]) -> bool:
        return self.any_ran if not required_tools else any(
            tool in self.attempted for tool in required_tools
        )


def _git(args: list[str], *, cwd: str | None = None, timeout: int = 300) -> str:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True,
                          timeout=timeout, check=False)
    return proc.stdout or ""


def _clone_url(repo: str) -> str:
    if repo.startswith(("http://", "https://", "file://", "git@")):
        return repo
    return f"https://github.com/{repo}.git"


def derive_pair(repo_dir: str, pattern: str, *, path_hint: str = "",
                expected_fix_commit: str = "", git=_git) -> tuple[str, str] | None:
    """Return ``(vulnerable_sha, fixed_sha)`` for the most recent commit that REMOVED ``pattern``
    (the fix) and its parent (the vulnerable revision), or None if no such commit exists."""
    log_args = ["-C", repo_dir, "log", "--all", "--format=%H", "-S", pattern]
    shas = [line.strip() for line in git(log_args).splitlines() if line.strip()]
    if expected_fix_commit:
        # Pin selection to the advisory commit, but still require repository history to prove
        # that this exact commit removed the ground-truth pattern. A supplied SHA cannot make
        # an unrelated diff scoreable.
        shas = [expected_fix_commit]
    for sha in shas:                    # newest first
        parent = git(["-C", repo_dir, "rev-parse", f"{sha}^"]).strip()
        if not parent:
            continue
        if path_hint:
            changed_paths = git(["-C", repo_dir, "diff", "--name-only", parent, sha])
            if path_hint.lower() not in changed_paths.lower():
                continue
        # `git show` intentionally suppresses ordinary diffs for many merge commits. Security
        # advisories can legitimately pin a merge SHA, so compare it explicitly to first-parent,
        # which is also the vulnerable revision returned by this function.
        diff = git(["-C", repo_dir, "diff", "--unified=0", parent, sha])
        removed = any(line.startswith("-") and pattern in line for line in diff.splitlines())
        added = any(line.startswith("+") and pattern in line for line in diff.splitlines())
        if removed and not added:       # net removal of the pattern -> this commit is the fix
            return (parent, sha)
    return None


def _matching_survivors(scan_root: str, case: RealCase) -> ScanObservation:
    """Scanners + reduction funnel over scan_root; return the tools whose surviving candidate
    matches this case's expected weakness (and path hint)."""
    from aegis.ai.candidate_reduction import reduce_candidates
    from aegis.ai.scope import filter_out_of_scope
    from aegis.ai.tool_bridge import ToolBridge, available_tools
    tools = list({t.name: t for lane in ("code", "secrets", "contract")
                  for t in available_tools(lane)
                  if not case.required_tools or t.name in case.required_tools}.values())
    if not tools:
        return ScanObservation(unavailable={"scanner-runtime": "no registered scanner binary installed"})
    # Semgrep's Python launcher can take more than the production daemon's five-second
    # steady-state probe budget on a cold CI/container filesystem. This benchmark is a bounded
    # batch job, so allow a cold-start probe without weakening the execution timeout or health
    # semantics.
    bridge = ToolBridge(timeout=300, runtime_manager=_benchmark_runtime())
    # This is a labelled ground-truth benchmark, not repository discovery: the advisory-backed
    # path is known and independently verified by the fix diff. Scan that source file when it is
    # unique, which prevents unrelated monorepo size from dominating detector recall. Fall back
    # to the checkout when the hint is absent or ambiguous.
    scan_target = scan_root
    if case.path_hint:
        matches = [
            path for path in Path(scan_root).rglob("*")
            if path.is_file() and case.path_hint.lower() in path.as_posix().lower()
        ]
        if len(matches) == 1:
            scan_target = str(matches[0])
    results = bridge.scan(scan_target, tools=tools)
    attempted = sorted(r.tool for r in results if r.ran)
    unavailable = {r.tool: r.error or "scanner did not run" for r in results if not r.ran}
    installed = {tool.name for tool in tools}
    for required in case.required_tools:
        if required not in installed:
            unavailable[required] = "required scanner binary is not installed"
    rows = bridge.findings(results)
    rows, _ = filter_out_of_scope(rows)
    red = reduce_candidates(rows)
    want = case.expected()
    hit: list[str] = []
    for c in red.survivors:
        text = f"{c.cwe} {c.rule} {c.summary}".lower()
        if want in text and (not case.path_hint or case.path_hint.lower() in c.path.lower()):
            hit.append(c.tool)
    return ScanObservation(sorted(set(hit)), attempted, unavailable)


@lru_cache(maxsize=1)
def _benchmark_runtime():
    """One immutable scanner health cache for the whole benchmark process."""
    from aegis.ai.tool_runtime import ToolRuntimeManager

    return ToolRuntimeManager(version_timeout=30)


def run_real_case(case: RealCase, *, workdir: str | None = None, git=_git,
                  scanner: Callable[[str, RealCase], ScanObservation] = _matching_survivors,
                  ) -> RealCaseResult:
    tmp = Path(workdir or tempfile.mkdtemp(prefix="aegis-realcve-"))
    tmp.mkdir(parents=True, exist_ok=True)
    repo_dir = tmp / case.id
    try:
        if case.expected_fix_commit:
            # The manifest pins the only history required for ground truth. Fetch exactly the
            # fix and its parent instead of cloning a monorepo's entire history (and doing that
            # repeatedly for repositories represented by several independent cases).
            repo_dir.mkdir(parents=True, exist_ok=True)
            git(["-C", str(repo_dir), "init", "--quiet"])
            git(["-C", str(repo_dir), "remote", "add", "origin", _clone_url(case.repo)])
            git([
                "-C", str(repo_dir), "fetch", "--quiet", "--depth=2", "origin",
                case.expected_fix_commit,
            ], timeout=600)
        else:
            git(["clone", "--quiet", _clone_url(case.repo), str(repo_dir)], timeout=600)
        if not (repo_dir / ".git").exists():
            return RealCaseResult(case.id, "skipped", "clone failed")
        if case.expected_fix_commit:
            present = git([
                "-C", str(repo_dir), "rev-parse", "--verify",
                f"{case.expected_fix_commit}^{{commit}}",
            ]).strip()
            if not present:
                git([
                    "-C", str(repo_dir), "fetch", "--quiet", "origin",
                    case.expected_fix_commit,
                ], timeout=600)
        pair = derive_pair(
            str(repo_dir), case.pattern, path_hint=case.path_hint,
            expected_fix_commit=case.expected_fix_commit, git=git,
        )
        if pair is None:
            reason = (
                "pinned fix commit does not remove the ground-truth pattern"
                if case.expected_fix_commit else
                "no fix commit removing the pattern found"
            )
            return RealCaseResult(case.id, "invalid", reason)
        vuln_ref, fix_ref = pair
        if case.expected_fix_commit and fix_ref != case.expected_fix_commit:
            return RealCaseResult(
                case.id, "invalid",
                f"derived fix {fix_ref} does not match pinned {case.expected_fix_commit}",
                vuln_ref, fix_ref,
            )
        git(["-C", str(repo_dir), "checkout", "--quiet", vuln_ref])
        vuln_scan = scanner(str(repo_dir), case)
        git(["-C", str(repo_dir), "checkout", "--quiet", fix_ref])
        fix_scan = scanner(str(repo_dir), case)
        if (not vuln_scan.can_score(case.required_tools)
                or not fix_scan.can_score(case.required_tools)):
            reasons = {**vuln_scan.unavailable, **fix_scan.unavailable}
            reason = "; ".join(f"{tool}: {error}" for tool, error in sorted(reasons.items()))
            return RealCaseResult(case.id, "unavailable", reason[:240], vuln_ref, fix_ref)
        if fix_scan.detectors:
            return RealCaseResult(case.id, "regressed",
                                  "detector still fires on the fixed revision",
                                  vuln_ref, fix_ref, fix_scan.detectors)
        if vuln_scan.detectors:
            return RealCaseResult(case.id, "detected", "", vuln_ref, fix_ref,
                                  vuln_scan.detectors)
        return RealCaseResult(case.id, "missed", "no matching finding at the vulnerable revision",
                              vuln_ref, fix_ref)
    except Exception as exc:
        return RealCaseResult(case.id, "skipped", f"{type(exc).__name__}: {exc}"[:160])


#: Built-in cases stay empty: production uses a reviewed, versioned JSON manifest selected by
#: AEGIS_REAL_CVE_CASES. The manifest pins advisory SHAs; the harness verifies their diffs.
CASES: tuple[RealCase, ...] = ()


def load_cases(path: str | Path) -> tuple[RealCase, ...]:
    """Load real-CVE cases and require independently verifiable upstream provenance.
    Pinned advisory SHAs are accepted only when their upstream diff removes the pattern."""
    import json
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    fields = set(RealCase.__dataclass_fields__)
    out: list[RealCase] = []
    seen: set[str] = set()
    for row in data if isinstance(data, list) else []:
        if isinstance(row, dict) and row.get("id") and row.get("repo") and row.get("pattern"):
            case = RealCase(**{k: v for k, v in row.items() if k in fields})
            if isinstance(case.required_tools, list):
                case = RealCase(**{**vars(case), "required_tools": tuple(case.required_tools)})
            if case.id in seen:
                raise ValueError(f"duplicate real-CVE case id: {case.id}")
            if case.expected_fix_commit and (
                len(case.expected_fix_commit) != 40
                or any(ch not in "0123456789abcdef" for ch in case.expected_fix_commit.lower())
            ):
                raise ValueError(f"{case.id}: expected_fix_commit must be a full 40-character SHA")
            if case.advisory_url and not case.advisory_url.startswith("https://"):
                raise ValueError(f"{case.id}: advisory_url must use https")
            seen.add(case.id)
            out.append(case)
    return tuple(out)


def _configured_cases() -> tuple[RealCase, ...]:
    import os
    manifest = os.environ.get("AEGIS_REAL_CVE_CASES", "").strip()
    if manifest and Path(manifest).is_file():
        return load_cases(manifest)
    return CASES


def run_real_bench(cases: tuple[RealCase, ...] | None = None) -> RealBenchResult:
    return RealBenchResult(cases=[run_real_case(c) for c in (cases or _configured_cases())])


def main(argv=None) -> int:
    import argparse
    import json
    import os

    parser = argparse.ArgumentParser(description="Measure Aegis against versioned real CVE fixes")
    parser.add_argument("--json", dest="json_path", help="write machine-readable results")
    args = parser.parse_args(argv)
    res = run_real_bench()
    print("AEGIS REAL-CVE GROUND TRUTH")
    print("-" * 72)
    for c in res.cases:
        print(f"  {c.status:9} {c.id:28} {','.join(c.detectors)} {c.reason}")
    s = res.summary()
    print("-" * 72)
    print(f"  scored {s['scored']}/{s['total']} | recall {s['recall']:.2f} | "
          f"regressions {s['regressions']} | {s['by_status']}")
    if not res.cases:
        print("  (no cases — set AEGIS_REAL_CVE_CASES=<manifest.json> with real-CVE entries; "
              "the harness derives the vulnerable/fixed commits itself)")
    if args.json_path:
        Path(args.json_path).write_text(json.dumps({
            "summary": s,
            "cases": [vars(case) for case in res.cases],
        }, indent=2, sort_keys=True), encoding="utf-8")
    strict = os.environ.get("AEGIS_REAL_CVE_STRICT", "").strip().lower() in {"1", "true", "yes"}
    if strict and (not res.measured or res.regressions or res.invalid):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
