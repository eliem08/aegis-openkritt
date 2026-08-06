"""Carpet sweep — a 24/7 deterministic hunter over every in-scope source target.

The cheapest path to a paid finding is the high-frequency classes that don't need the slow LLM
pass: JWT auth flaws (CWE-347/798), unrestricted uploads (CWE-434), and hardcoded secrets.
This runs those detectors continuously across EVERY in-scope source-code program in the
registry — and keeps going as the monitor/importers add more — so nothing eligible goes
un-swept and fresh code gets hit the moment it appears.

Design for always-on:
  * pool = every active program with a GitHub repo target (refreshed each cycle; an optional
    import pulls newly-launched programs in). Only in-scope program repos — never a random
    repo; the authorization boundary holds.
  * skip-unchanged: each repo's last-swept commit is remembered; a repo is re-scanned only
    when its HEAD changes. So a cycle is cheap and *fresh commits* are what actually trigger
    work — the fresh-code edge, automated.
  * fast lanes only: semgrep (bundled JWT/upload/PHP/Ruby rules) + gitleaks + detect-secrets
    + njsscan. No LLM, no SCA-of-dependencies noise.
  * concurrent across repos, bounded. Hits ranked by program reward x severity, persisted for
    the dashboard. Candidates only — a human still reproduces + submits.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

# fast, high-signal, no-LLM tools. (Excludes slow/whole-build or SCA tools: gosec, psalm,
# mythril, trivy, grype, osv-scanner, checkov, brakeman — those belong in the deep hunt.)
FAST_TOOLS = ("semgrep", "gitleaks", "detect-secrets", "njsscan")
HITS_FILE = "reports/carpet_hits.json"
STATE_FILE = "reports/carpet_state.json"
_MAX_HITS = 2000
_SEV_RANK = {"critical": 4, "high": 3, "error": 3, "medium": 2, "warning": 2, "low": 1, "info": 0}


@dataclass
class Hit:
    program: str
    handle: str
    platform: str
    reward: float
    repo: str
    detector: str
    cwe: str
    severity: str
    file: str
    line: int
    message: str
    commit: str = ""
    ts: float = 0.0
    triage: str = ""            # hostile-triager verdict: pass | downgrade | needs_evidence
    triage_reason: str = ""

    def score(self) -> float:
        # a triager-confirmed 'pass' outranks an untriaged/needs-evidence hit of equal reward
        bump = {"pass": 1.6, "downgrade": 1.2, "needs_evidence": 1.0}.get(self.triage, 1.1)
        return self.reward * (1 + _SEV_RANK.get((self.severity or "").lower(), 1)) * bump


def _excerpt(clone_path, rel_file, line, ctx=45) -> str:
    """The enclosing ~90 lines around a hit — enough for the triager to see adjacent guards
    (e.g. a jwt.verify right after a jwt.decode, which is what made the juice-shop hit an FP)."""
    try:
        lines = (Path(clone_path) / rel_file).read_text(encoding="utf-8",
                                                         errors="ignore").splitlines()
        lo, hi = max(0, line - ctx), min(len(lines), line + ctx)
        return "\n".join(lines[lo:hi])[:8000]
    except Exception:
        return ""


def _fast_tools():
    from .tool_bridge import resolve_binary
    from .tool_registry import TOOLS
    return [t for t in TOOLS if t.name in FAST_TOOLS and resolve_binary(t.binary)]


def _load(path: str, default):
    p = Path(path)
    if not p.is_file():
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _save(path: str, obj) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2), encoding="utf-8")


def _row_to_hit(program, repo, tool_name, commit, row, repo_root="") -> Hit | None:
    a = row.get("json_answer") or {}
    fp = str(a.get("file_path") or "")
    if not fp:
        return None
    # scanners emit absolute clone-cache paths; show the path RELATIVE to the repo root so a
    # hit reads "routes/verify.ts" not "reports/clones/owner__repo/routes/verify.ts".
    norm = fp.replace("\\", "/")
    root = str(repo_root).replace("\\", "/").rstrip("/")
    if root and root in norm:
        fp = norm.split(root, 1)[1].lstrip("/")
    return Hit(
        program=program.handle, handle=program.handle, platform=program.platform,
        reward=float(program.reward_ceiling or 0), repo=repo, detector=tool_name,
        cwe=str(a.get("vulnerability_type") or a.get("cwe") or "")[:60],
        severity=str(row.get("severity") or a.get("severity") or "warning"),
        file=fp, line=int(a.get("line") or 0) or 0,
        message=str(a.get("summary") or a.get("explanation") or "")[:240],
        commit=commit, ts=time.time())


def _triage_hits(hits, clone_path, triager) -> list:
    """Run each raw hit through the hostile-triager, which reads the enclosing code and rejects
    false positives (a decode guarded by an adjacent verify, a check in dead/non-auth code...).
    Drops 'reject'; keeps pass/downgrade/needs_evidence with the verdict attached. On any
    triager error the hit is kept untriaged (never silently lost)."""
    kept = []
    for h in hits:
        src = _excerpt(clone_path, h.file, h.line)
        row = {"json_answer": {"vulnerability_type": h.cwe, "summary": h.message,
                               "file_path": h.file, "line": h.line},
               "severity": h.severity, "location": f"{h.file}:{h.line}"}
        t = triager.triage(row, scope_text="", source=src)
        v = t.get("verdict", "unreviewed")
        if v == "reject":
            continue                                     # confirmed false positive — drop it
        h.triage = v if v in ("pass", "downgrade", "needs_evidence") else ""
        h.triage_reason = str(t.get("reason", ""))[:300]
        if v == "downgrade":
            h.severity = t.get("corrected_severity", h.severity)
        kept.append(h)
    return kept


def sweep_repo(program, repo, *, tools, state, cache_dir, token, timeout, force=False,
               triager=None):
    """Clone (shallow, cached) + run the fast tools on one repo. Returns (hits, skipped).
    If a triager is given, raw hits are auto-triaged (FPs dropped) before returning."""
    from .repo_clone import clone_repository
    from .tool_bridge import ToolBridge
    try:
        clone = clone_repository(repo, cache_dir=cache_dir, token=token, depth=1, refresh=True)
    except Exception:
        return [], False
    commit = clone.commit or ""
    prev = (state.get(repo) or {}).get("commit")
    if commit and prev == commit and not force:
        return [], True                                  # unchanged since last sweep — skip
    results = ToolBridge(timeout=timeout).scan(str(clone.path), tools=tools)
    hits = [h for h in (_row_to_hit(program, repo, r.tool, commit, row, str(clone.path))
                        for r in results for row in r.findings) if h]
    if triager is not None and hits:
        hits = _triage_hits(hits, str(clone.path), triager)
    state[repo] = {"commit": commit, "ts": time.time(), "hits": len(hits)}
    return hits, False


def _open_triager():
    """Open an LLM-backed hostile-triager if AEGIS_CARPET_TRIAGE is on and a client can be
    built. Returns (triager, client_cm) — the caller keeps client_cm open during the sweep.
    (None, None) when triage is off or unavailable (sweep then returns raw hits)."""
    if os.environ.get("AEGIS_CARPET_TRIAGE", "").strip().lower() not in ("1", "true", "yes"):
        return None, None
    try:
        from .client import DeepSeekClient
        from .config import DeepSeekConfig
        from .triager import HostileTriager
        cm = DeepSeekClient(DeepSeekConfig.from_env())
        return HostileTriager, cm      # instantiate the triager once the client is entered
    except Exception:
        return None, None


def sweep_once(programs=None, *, concurrency=None, timeout=None, hits_file=HITS_FILE,
               state_file=STATE_FILE, on_hit=None, force=False, triager=None) -> dict:
    """One pass over every in-scope source repo. Persists ranked hits + per-repo state.
    If AEGIS_CARPET_TRIAGE=1, each raw hit is auto-triaged (FPs dropped) before it's kept."""
    import contextlib

    from .registry import load_registry
    programs = programs if programs is not None else load_registry()
    tools = _fast_tools()
    token = os.environ.get("GITHUB_TOKEN", "")
    cache_dir = os.environ.get("AEGIS_CLONE_DIR") or "reports/clones"
    timeout = timeout or int(os.environ.get("AEGIS_SCANNER_TIMEOUT", "120") or 120)
    workers = concurrency or int(os.environ.get("AEGIS_CARPET_CONCURRENCY", "4") or 4)
    state = _load(state_file, {})
    prior = _load(hits_file, [])

    jobs = [(p, repo) for p in programs if p.active
            for repo in (p.targets or []) if repo.count("/") == 1]
    new_hits: list[Hit] = []
    swept = skipped = 0

    with contextlib.ExitStack() as stack:
        if triager is None:               # not injected by a test — build from env if enabled
            Trg, cm = _open_triager()
            if cm is not None:
                triager = Trg(stack.enter_context(cm))

        def _work(job):
            p, repo = job
            return sweep_repo(p, repo, tools=tools, state=state, cache_dir=cache_dir,
                              token=token, timeout=timeout, force=force, triager=triager)

        if workers > 1 and len(jobs) > 1:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futs = [ex.submit(_work, j) for j in jobs]
                for fut in as_completed(futs):
                    try:
                        hits, was_skip = fut.result()
                    except Exception:
                        continue
                    skipped += 1 if was_skip else 0
                    swept += 0 if was_skip else 1
                    for h in hits:
                        new_hits.append(h)
                        if on_hit:
                            on_hit(h)
        else:
            for j in jobs:
                hits, was_skip = _work(j)
                skipped += 1 if was_skip else 0
                swept += 0 if was_skip else 1
                new_hits.extend(hits)

    # merge: dedup by (repo, file, line, cwe); newest hit wins; rank by reward x severity
    merged = {}
    for h in [Hit(**x) if isinstance(x, dict) else x for x in prior] + new_hits:
        merged[(h.repo, h.file, h.line, h.cwe)] = h
    ranked = sorted(merged.values(), key=lambda h: -h.score())[:_MAX_HITS]
    _save(hits_file, [asdict(h) for h in ranked])
    _save(state_file, state)
    return {"repos_total": len(jobs), "swept": swept, "skipped_unchanged": skipped,
            "new_hits": len(new_hits), "total_hits": len(ranked),
            "tools": [t.name for t in tools]}


def run_forever(*, interval=None, import_every=None) -> None:
    """The 24/7 loop: refresh the pool, sweep everything changed, sleep, repeat. Optionally
    re-import program feeds every N cycles so newly-launched programs enter the pool."""
    interval = interval or int(os.environ.get("AEGIS_CARPET_INTERVAL", "1800") or 1800)
    import_every = import_every or int(os.environ.get("AEGIS_CARPET_IMPORT_EVERY", "12") or 12)
    cycle = 0
    while True:
        cycle += 1
        try:
            if import_every and cycle % import_every == 1:
                try:
                    from .program_sources import import_programs
                    import_programs()
                except Exception:
                    pass
            summary = sweep_once()
            summary["cycle"] = cycle
            _save("reports/carpet_last.json", summary)
        except Exception as exc:
            _save("reports/carpet_last.json", {"cycle": cycle, "error": str(exc)[:200]})
        time.sleep(max(60, interval))


def load_hits(limit: int = 100, report_dir: str = "reports") -> list[dict]:
    return (_load(str(Path(report_dir) / "carpet_hits.json"), []) or [])[:limit]


def main(argv=None) -> int:
    import sys
    args = list(argv if argv is not None else sys.argv[1:])
    if "--forever" in args:
        run_forever()
        return 0
    s = sweep_once(force="--force" in args)
    print(f"carpet sweep — tools: {', '.join(s['tools'])}")
    print(f"  repos {s['repos_total']} · swept {s['swept']} · skipped(unchanged) {s['skipped_unchanged']}")
    print(f"  new hits {s['new_hits']} · total stored {s['total_hits']}")
    for h in load_hits(15):
        print(f"  [{h['severity']:8}] ${int(h['reward']):>7,} {h['detector']:8} {h['cwe'][:22]:22} "
              f"{h['repo']}:{h['file']}:{h['line']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
