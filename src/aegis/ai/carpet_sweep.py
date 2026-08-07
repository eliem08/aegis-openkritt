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
  * concurrent across repos, bounded. Hits ranked by program reward x severity x scanner signal, persisted for
    the dashboard. Candidates only — a human still reproduces + submits.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

# fast, high-signal, no-LLM tools. njsscan was DROPPED: across every repo swept (vercel,
# svelte, ExodusOSS) 100% of its hits were false positives — it matches identifier NAMES
# ("...Secret", "...Password"), every Math.random, and every === without proving reachability
# or that a value is actually a secret. Keep the precise ones: our curated semgrep rules
# (JWT/upload/PHP/Ruby sinks) + gitleaks/detect-secrets (entropy-based real secrets).
# (Also excludes slow whole-build/SCA tools: gosec, psalm, mythril, trivy, grype, osv, checkov.)
FAST_TOOLS = ("semgrep", "gitleaks", "detect-secrets")
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
    signal: float = 0.5
    rule_id: str = ""
    detectors: list[str] = field(default_factory=list)
    evidence_count: int = 1
    corroborated: bool = False

    def score(self) -> float:
        """Rank by payout potential *and* deterministic scanner signal.

        A large bounty no longer floats a weak pattern-only warning above a high-confidence
        source-to-sink result. Independent scanners agreeing on one location add a modest
        boost, but never convert the observation into a confirmed finding.
        """
        signal = min(1.0, max(0.20, float(self.signal or 0.0)))
        evidence = max(1, int(self.evidence_count or 1))
        corroboration = 1.0 + min(0.50, 0.20 * (evidence - 1))
        return (self.reward * (1 + _SEV_RANK.get((self.severity or "").lower(), 1))
                * signal * corroboration)


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


def _persist(prior, new_hits, hits_file) -> list:
    """Merge, corroborate and rank scanner observations.

    Deduplication is by repo/file/line/CWE. When independent scanners hit the same location,
    their names are retained and the candidate is marked corroborated. This raises review
    priority but deliberately does not mark the finding confirmed.
    """
    fields = set(Hit.__dataclass_fields__)

    def _coerce(value):
        if not isinstance(value, dict):
            return value
        return Hit(**{k: v for k, v in value.items() if k in fields})

    merged = {}
    for h in [_coerce(x) for x in prior] + new_hits:
        if not h.detectors:
            h.detectors = [h.detector] if h.detector else []
        key = (h.repo, h.file, h.line, h.cwe)
        current = merged.get(key)
        if current is None:
            h.evidence_count = max(1, len(set(h.detectors)))
            h.corroborated = h.evidence_count > 1
            merged[key] = h
            continue
        detectors = sorted(set(current.detectors or [current.detector])
                           | set(h.detectors or [h.detector]))
        current.detectors = [d for d in detectors if d]
        current.evidence_count = max(1, len(current.detectors))
        current.corroborated = current.evidence_count > 1
        current.signal = max(float(current.signal or 0.0), float(h.signal or 0.0))
        if h.score() > current.score():
            current.detector = h.detector
            current.message = h.message
            current.severity = h.severity
            current.rule_id = h.rule_id
            current.commit = h.commit or current.commit
            current.ts = max(current.ts, h.ts)
    ranked = sorted(merged.values(), key=lambda h: -h.score())[:_MAX_HITS]
    _save(hits_file, [asdict(h) for h in ranked])
    return ranked


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
    severity = str(row.get("severity") or a.get("severity") or "warning").lower()
    fallback_signal = {"critical": 0.90, "high": 0.82, "error": 0.82,
                       "medium": 0.62, "warning": 0.62, "low": 0.42, "info": 0.30}
    try:
        signal = float(row.get("confidence") or 0.0)
    except (TypeError, ValueError):
        signal = 0.0
    signal = min(1.0, max(0.0, signal or fallback_signal.get(severity, 0.50)))
    try:
        min_signal = float(os.environ.get("AEGIS_CARPET_MIN_SIGNAL", "0.50") or 0.50)
    except ValueError:
        min_signal = 0.50
    if signal < min_signal:
        return None
    metadata = row.get("scanner_metadata") or {}
    return Hit(
        program=program.handle, handle=program.handle, platform=program.platform,
        reward=float(program.reward_ceiling or 0), repo=repo, detector=tool_name,
        cwe=str(a.get("vulnerability_type") or a.get("cwe") or "")[:60],
        severity=severity, file=fp, line=int(a.get("line") or 0) or 0,
        message=str(a.get("summary") or a.get("explanation") or "")[:240],
        commit=commit, ts=time.time(), signal=signal,
        rule_id=str(metadata.get("rule_id") or "")[:160], detectors=[tool_name])


def _tree_size_mb(path, skip=frozenset({".git", "node_modules", "vendor"})) -> float:
    """Working-tree size in MB (for reporting only — nothing is skipped from scanning)."""
    total = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in skip]
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return round(total / 1024 / 1024, 1)


def sweep_repo(program, repo, *, tools, state, cache_dir, token, timeout, force=False):
    """Clone (shallow, cached) + run the fast tools on one repo. Scans EVERYTHING — no size
    cap, no skip. Returns (hits, skipped, secs, size_mb). Raw hits; a human debugs each."""
    from .repo_clone import clone_repository
    from .tool_bridge import ToolBridge
    t0 = time.monotonic()
    try:
        clone = clone_repository(repo, cache_dir=cache_dir, token=token, depth=1, refresh=True)
    except Exception:
        return [], False, round(time.monotonic() - t0, 1), 0.0
    commit = clone.commit or ""
    prev = (state.get(repo) or {}).get("commit")
    if commit and prev == commit and not force:
        return [], True, round(time.monotonic() - t0, 1), 0.0   # unchanged — skip
    size_mb = _tree_size_mb(clone.path)
    results = ToolBridge(timeout=timeout).scan(str(clone.path), tools=tools)  # timeout None = unbounded
    hits = [h for h in (_row_to_hit(program, repo, r.tool, commit, row, str(clone.path))
                        for r in results for row in r.findings) if h]
    state[repo] = {"commit": commit, "ts": time.time(), "hits": len(hits), "mb": size_mb}
    return hits, False, round(time.monotonic() - t0, 1), size_mb


def _resolve_timeout(timeout):
    """Unbounded by default (scan everything). AEGIS_CARPET_TIMEOUT=0/unset -> None (no
    timeout); a positive value caps per-scanner wall time."""
    if timeout is not None:
        return timeout
    t = os.environ.get("AEGIS_CARPET_TIMEOUT")
    if t in (None, "", "0", "none", "None"):
        return None
    try:
        return int(t)
    except ValueError:
        return None


def sweep_once(programs=None, *, concurrency=None, timeout=None, hits_file=HITS_FILE,
               state_file=STATE_FILE, on_hit=None, force=False, progress=None) -> dict:
    """One pass over every in-scope source repo — scans EVERYTHING, no size cap, no timeout by
    default. Persists ranked RAW hits + per-repo state. `progress(kind, data)` streams live
    events. Hits are leads — a human (Claude, then the operator) debugs each one."""
    from .registry import load_registry
    programs = programs if programs is not None else load_registry()
    tools = _fast_tools()
    token = os.environ.get("GITHUB_TOKEN", "")
    cache_dir = os.environ.get("AEGIS_CLONE_DIR") or "reports/clones"
    timeout = _resolve_timeout(timeout)
    workers = concurrency or int(os.environ.get("AEGIS_CARPET_CONCURRENCY", "4") or 4)
    state = _load(state_file, {})
    prior = _load(hits_file, [])
    emit = progress or (lambda *_: None)

    jobs = [(p, repo) for p in programs if p.active
            for repo in (p.targets or []) if repo.count("/") == 1]
    emit("start", {"repos": len(jobs), "tools": [t.name for t in tools], "workers": workers,
                   "timeout": timeout})
    new_hits: list[Hit] = []
    swept = skipped = done = 0
    n = len(jobs)

    def _work(job):
        p, repo = job
        return (repo,) + sweep_repo(p, repo, tools=tools, state=state, cache_dir=cache_dir,
                                    token=token, timeout=timeout, force=force)

    def _record(repo, hits, was_skip, secs, mb):
        nonlocal swept, skipped, done
        done += 1
        skipped += 1 if was_skip else 0
        swept += 0 if was_skip else 1
        for h in hits:
            new_hits.append(h)
            if on_hit:
                on_hit(h)
        # persist per-repo: hits land in the file the instant they're found (real-time
        # debuggable), and state saves each repo so a restart resumes via skip-unchanged.
        if hits:
            _persist(prior, new_hits, hits_file)
        _save(state_file, state)
        emit("repo", {"i": done, "n": n, "repo": repo, "hits": len(hits), "secs": secs,
                      "mb": mb, "skipped": was_skip, "running_hits": len(new_hits)})

    if workers > 1 and len(jobs) > 1:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(_work, j) for j in jobs]
            for fut in as_completed(futs):
                try:
                    repo, hits, was_skip, secs, mb = fut.result()
                except Exception:
                    continue
                _record(repo, hits, was_skip, secs, mb)
    else:
        for j in jobs:
            repo, hits, was_skip, secs, mb = _work(j)
            _record(repo, hits, was_skip, secs, mb)

    # final merge/rank/persist (also written incrementally per-repo in _record)
    ranked = _persist(prior, new_hits, hits_file)
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


def _cli_printer():
    """A live progress printer for the CLI: repos found, each repo as it's scanned with timing
    + hit count, a running total, and every hit inline."""
    t0 = [0.0]

    def emit(kind, d):
        if kind == "start":
            t0[0] = time.monotonic()
            to = d["timeout"]
            print(f"\n🧹 CARPET SWEEP — {d['repos']} in-scope repos found | tools: "
                  f"{', '.join(d['tools'])} | {d['workers']} parallel | "
                  f"timeout: {'none (scan everything)' if to is None else str(to)+'s'}\n"
                  + "-" * 78, flush=True)
        elif kind == "repo":
            el = time.monotonic() - t0[0]
            tag = ("· unchanged" if d["skipped"]
                   else (f"→ {d['hits']} HIT(S)" if d["hits"] else "clean"))
            mark = "🔴" if d["hits"] else ("  " if d["skipped"] else "✓ ")
            print(f"{mark}[{d['i']:>3}/{d['n']}] {d['repo']:<44} {d['mb']:>6}MB "
                  f"{d['secs']:>6.1f}s  {tag:<12} | total hits: {d['running_hits']} "
                  f"| elapsed {el/60:.1f}m", flush=True)
    return emit


def main(argv=None) -> int:
    import sys
    args = list(argv if argv is not None else sys.argv[1:])
    if "--forever" in args:
        # 24/7: sweep, sleep, repeat — printing each cycle
        pr = _cli_printer()
        while True:
            s = sweep_once(force="--force" in args, progress=pr)
            print("-" * 78)
            print(f"CYCLE DONE — swept {s['swept']} · unchanged {s['skipped_unchanged']} · "
                  f"new hits {s['new_hits']} · stored {s['total_hits']}")
            print("TOP HITS:")
            for h in load_hits(20):
                print(f"  [{h['severity']:8}] ${int(h['reward']):>7,} {h['detector']:9} "
                      f"{h['cwe'][:22]:22} {h['repo']}:{h['file']}:{h['line']}")
            gap = int(os.environ.get("AEGIS_CARPET_INTERVAL", "1800") or 1800)
            print(f"\n😴 sleeping {gap}s, then re-sweeping changed repos…\n", flush=True)
            time.sleep(max(60, gap))
    s = sweep_once(force="--force" in args, progress=_cli_printer())
    print("-" * 78)
    print(f"DONE — {s['repos_total']} repos · swept {s['swept']} · unchanged "
          f"{s['skipped_unchanged']} · new hits {s['new_hits']} · stored {s['total_hits']}")
    print("\nTOP HITS (reward × severity):")
    for h in load_hits(25):
        print(f"  [{h['severity']:8}] ${int(h['reward']):>7,} {h['detector']:9} {h['cwe'][:22]:22} "
              f"{h['repo']}:{h['file']}:{h['line']}")
    print("\nfull list: reports/carpet_hits.json  ·  next: point Claude at any hit to debug it")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
