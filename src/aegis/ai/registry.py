"""Program registry — the persistent store of bounty-program records.

The single most repeated point in mdp_sec's write-up: *before a model touches a target the
system already knows what is in scope, what the program pays, and which rules apply*. His
dashboard holds 3,636 such records. This is the local, file-backed version of that — one
JSON store the hunt reads before every run so scope, exclusions, rewards and rules are
known up front instead of re-derived per run.

It composes the pieces already built:
  * `scope_text` flows straight into the analysis prompt via `scope.scope_prompt` and the
    out-of-scope dependency filter (`scope.filter_out_of_scope`).
  * `to_hunt_target()` produces the `HuntTarget` the profit/EV ranker consumes.
  * maturity fields (`audits`, `age_months`, `paid_reports`) feed target-selection scoring
    (`selection.py`) — the "don't burn a run on an over-audited protocol" lever.

A program record is DATA describing a target. Its `rules`/`scope_text` are never executed
as instructions — they only shape filtering, prompting and ranking. Nothing here submits,
tests a live system, or acts on a program's behalf; a human still picks and approves.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

DEFAULT_STORE = "reports/programs.json"


@dataclass
class Program:
    handle: str                                  # program slug, e.g. "acme" (unique key)
    platform: str = ""                           # hackerone | immunefi | bugcrowd | intigriti | ...
    url: str = ""
    targets: list[str] = field(default_factory=list)     # in-scope repos/assets (owner/repo or 0x…)
    kind: str = "repo"                            # "repo" | "contract" — default for its targets
    subpath: str = ""                            # focus subtree for monorepos
    out_of_scope: list[str] = field(default_factory=list)  # excluded assets/paths/classes
    reward_ceiling: float = 0.0
    reward_floor: float = 0.0
    rules: str = ""                              # program rules / notes (freeform)
    scope_text: str = ""                         # raw scope page — primes the analysis prompt
    # maturity signals for selection scoring (mdp_sec: ~80% of targets yield nothing; the
    # over-audited, long-live programs are the least likely to pay a fresh run):
    audits: int = 0                              # number of prior security audits
    age_months: int = 0                          # how long the program/protocol has been live
    paid_reports: int = 0                        # known count of already-paid reports (crowding)
    # EV inputs (fall back to sane priors when unknown):
    findability: float = 0.5
    saturation: float = 0.0
    active: bool = True                          # skip paused/retired programs in selection
    notes: str = ""

    def scope_bundle(self) -> str:
        """The text the LLM should read as scope: the explicit scope page plus a compact
        rendering of the structured in/out-of-scope lists and rules, so even a record with
        no pasted page still scopes the model."""
        parts: list[str] = []
        if self.scope_text.strip():
            parts.append(self.scope_text.strip())
        if self.targets:
            parts.append("In scope: " + ", ".join(self.targets))
        if self.out_of_scope:
            parts.append("Out of scope: " + ", ".join(self.out_of_scope))
        if self.rules.strip():
            parts.append("Rules: " + self.rules.strip())
        return "\n".join(parts).strip()


def _store_path(path: str | Path | None) -> Path:
    return Path(path or DEFAULT_STORE)


def load_registry(path: str | Path | None = None) -> list[Program]:
    """Load all program records. Missing/empty store -> []. Tolerates unknown keys so an
    older/newer store shape never crashes a run."""
    p = _store_path(path)
    if not p.is_file():
        return []
    try:
        raw = json.loads(p.read_text(encoding="utf-8") or "[]")
    except (json.JSONDecodeError, OSError):
        return []
    fields = {f for f in Program.__dataclass_fields__}
    progs: list[Program] = []
    for rec in raw if isinstance(raw, list) else []:
        if isinstance(rec, dict) and rec.get("handle"):
            progs.append(Program(**{k: v for k, v in rec.items() if k in fields}))
    return progs


def save_registry(programs: list[Program], path: str | Path | None = None) -> None:
    p = _store_path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps([asdict(x) for x in programs], indent=2), encoding="utf-8")


def upsert(program: Program, path: str | Path | None = None) -> list[Program]:
    """Add or replace a program by handle, persist, and return the new registry."""
    progs = [x for x in load_registry(path) if x.handle != program.handle]
    progs.append(program)
    save_registry(progs, path)
    return progs


def get_program(handle: str, path: str | Path | None = None) -> Program | None:
    for x in load_registry(path):
        if x.handle == handle:
            return x
    return None


def scope_text_for(handle: str, path: str | Path | None = None) -> str:
    """The scope bundle for a program handle — feed to RepoHuntConfig.scope_text."""
    prog = get_program(handle, path)
    return prog.scope_bundle() if prog else ""


def to_hunt_targets(programs: list[Program] | None = None,
                    path: str | Path | None = None) -> list:
    """Expand active program records into HuntTargets (one per in-scope target asset), so the
    EV/profit ranker can score them. Inactive programs are skipped."""
    from .auto_hunt import HuntTarget
    progs = programs if programs is not None else load_registry(path)
    out: list[HuntTarget] = []
    for pr in progs:
        if not pr.active:
            continue
        for asset in (pr.targets or [""]):
            if not asset:
                continue
            out.append(HuntTarget(
                repository=asset, handle=pr.handle, reward_ceiling=pr.reward_ceiling,
                findability=pr.findability, subpath=pr.subpath, kind=pr.kind,
                saturation=pr.saturation))
    return out
