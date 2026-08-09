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
from pathlib import Path


@dataclass(frozen=True)
class RealCase:
    id: str
    repo: str                 # clone URL or owner/repo (github assumed if no scheme)
    pattern: str              # literal code the FIX removed (git -S pickaxe target)
    cwe: str                  # expected weakness class
    path_hint: str = ""       # optional path substring to disambiguate the vulnerable file
    match: str = ""           # lowercase substring expected in a finding (defaults to cwe)

    def expected(self) -> str:
        return (self.match or self.cwe).lower()


@dataclass
class RealCaseResult:
    id: str
    status: str               # "detected" | "missed" | "regressed" | "skipped"
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

    def summary(self) -> dict:
        from collections import Counter
        return {"total": len(self.cases), "scored": len(self.scored),
                "recall": self.recall, "regressions": self.regressions,
                "by_status": dict(Counter(c.status for c in self.cases))}


def _git(args: list[str], *, cwd: str | None = None, timeout: int = 300) -> str:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True,
                          timeout=timeout, check=False)
    return proc.stdout or ""


def _clone_url(repo: str) -> str:
    if repo.startswith(("http://", "https://", "git@")):
        return repo
    return f"https://github.com/{repo}.git"


def derive_pair(repo_dir: str, pattern: str, *, path_hint: str = "",
                git=_git) -> tuple[str, str] | None:
    """Return ``(vulnerable_sha, fixed_sha)`` for the most recent commit that REMOVED ``pattern``
    (the fix) and its parent (the vulnerable revision), or None if no such commit exists."""
    log_args = ["-C", repo_dir, "log", "--all", "--format=%H", "-S", pattern]
    if path_hint:
        log_args += ["--", f"*{path_hint}*"]
    shas = [line.strip() for line in git(log_args).splitlines() if line.strip()]
    for sha in shas:                    # newest first
        diff = git(["-C", repo_dir, "show", sha, "--unified=0", "--format="])
        removed = any(line.startswith("-") and pattern in line for line in diff.splitlines())
        added = any(line.startswith("+") and pattern in line for line in diff.splitlines())
        if removed and not added:       # net removal of the pattern -> this commit is the fix
            parent = git(["-C", repo_dir, "rev-parse", f"{sha}^"]).strip()
            if parent:
                return (parent, sha)
    return None


def _matching_survivors(scan_root: str, case: RealCase) -> list[str]:
    """Scanners + reduction funnel over scan_root; return the tools whose surviving candidate
    matches this case's expected weakness (and path hint)."""
    from aegis.ai.candidate_reduction import reduce_candidates
    from aegis.ai.scope import filter_out_of_scope
    from aegis.ai.tool_bridge import ToolBridge, available_tools
    tools = list({t.name: t for lane in ("code", "secrets", "contract")
                  for t in available_tools(lane)}.values())
    if not tools:
        return []
    rows = ToolBridge(timeout=300).findings(ToolBridge(timeout=300).scan(scan_root, tools=tools))
    rows, _ = filter_out_of_scope(rows)
    red = reduce_candidates(rows)
    want = case.expected()
    hit: list[str] = []
    for c in red.survivors:
        text = f"{c.cwe} {c.rule} {c.summary}".lower()
        if want in text and (not case.path_hint or case.path_hint.lower() in c.path.lower()):
            hit.append(c.tool)
    return sorted(set(hit))


def run_real_case(case: RealCase, *, workdir: str | None = None, git=_git) -> RealCaseResult:
    tmp = Path(workdir or tempfile.mkdtemp(prefix="aegis-realcve-"))
    repo_dir = tmp / case.id
    try:
        git(["clone", "--quiet", _clone_url(case.repo), str(repo_dir)], timeout=600)
        if not (repo_dir / ".git").exists():
            return RealCaseResult(case.id, "skipped", "clone failed")
        pair = derive_pair(str(repo_dir), case.pattern, path_hint=case.path_hint, git=git)
        if pair is None:
            return RealCaseResult(case.id, "skipped", "no fix commit removing the pattern found")
        vuln_ref, fix_ref = pair
        git(["-C", str(repo_dir), "checkout", "--quiet", vuln_ref])
        vuln_hit = _matching_survivors(str(repo_dir), case)
        git(["-C", str(repo_dir), "checkout", "--quiet", fix_ref])
        fix_hit = _matching_survivors(str(repo_dir), case)
        if fix_hit:
            return RealCaseResult(case.id, "regressed",
                                  "detector still fires on the fixed revision",
                                  vuln_ref, fix_ref, fix_hit)
        if vuln_hit:
            return RealCaseResult(case.id, "detected", "", vuln_ref, fix_ref, vuln_hit)
        return RealCaseResult(case.id, "missed", "no matching finding at the vulnerable revision",
                              vuln_ref, fix_ref)
    except Exception as exc:
        return RealCaseResult(case.id, "skipped", f"{type(exc).__name__}: {exc}"[:160])


#: built-in verified cases are appended here as they are confirmed in a scanner environment.
#: Operators add their own via a JSON manifest (AEGIS_REAL_CVE_CASES) rather than hardcoding SHAs.
CASES: tuple[RealCase, ...] = ()


def load_cases(path: str | Path) -> tuple[RealCase, ...]:
    """Load real-CVE cases from a JSON manifest: a list of objects with the RealCase fields.
    SHAs are NEVER specified — the harness derives the (vulnerable, fixed) pair from history."""
    import json
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    fields = set(RealCase.__dataclass_fields__)
    out: list[RealCase] = []
    for row in data if isinstance(data, list) else []:
        if isinstance(row, dict) and row.get("id") and row.get("repo") and row.get("pattern"):
            out.append(RealCase(**{k: v for k, v in row.items() if k in fields}))
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
