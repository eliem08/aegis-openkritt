"""Program registry — the persistent store of bounty-program records.

The registry is the canonical local snapshot used for target selection and authorization.
Every upstream-derived record can carry source/scope retrieval timestamps so automated hunts
can fail closed when scope data is stale. Asset-level bounty eligibility is kept separately
from submission eligibility because "in scope" does not necessarily mean "paid".
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path

DEFAULT_STORE = "reports/programs.json"
_STORE_LOCK = threading.RLock()


@dataclass
class Program:
    handle: str                                  # program slug, e.g. "acme" (unique key)
    platform: str = ""                           # hackerone | immunefi | bugcrowd | intigriti | ...
    url: str = ""
    targets: list[str] = field(default_factory=list)     # submission-eligible repos/assets
    bounty_eligible_targets: list[str] = field(default_factory=list)  # explicitly paid assets
    kind: str = "repo"                            # "repo" | "contract" — default for its targets
    subpath: str = ""                            # focus subtree for monorepos
    out_of_scope: list[str] = field(default_factory=list)  # excluded assets/paths/classes
    reward_ceiling: float = 0.0
    reward_floor: float = 0.0
    rules: str = ""                              # program rules / notes (freeform)
    scope_text: str = ""                         # raw scope page — primes the analysis prompt
    source_retrieved_at: str = ""                # when the upstream program record was fetched
    scope_retrieved_at: str = ""                 # when structured scope was fetched/verified
    # maturity signals for selection scoring
    audits: int = 0
    age_months: int = 0
    paid_reports: int = 0
    # EV inputs (fall back to sane priors when unknown):
    findability: float = 0.5
    saturation: float = 0.0
    active: bool = True                          # skip paused/retired programs in selection
    notes: str = ""

    def scope_bundle(self) -> str:
        """Render the exact scope/rules snapshot consumed by analysis and authorization."""
        parts: list[str] = []
        if self.scope_text.strip():
            parts.append(self.scope_text.strip())
        if self.targets:
            parts.append("In scope: " + ", ".join(self.targets))
        if self.bounty_eligible_targets:
            parts.append("Bounty eligible: " + ", ".join(self.bounty_eligible_targets))
        if self.out_of_scope:
            parts.append("Out of scope: " + ", ".join(self.out_of_scope))
        if self.rules.strip():
            parts.append("Rules: " + self.rules.strip())
        return "\n".join(parts).strip()


def _store_path(path: str | Path | None) -> Path:
    return Path(path or DEFAULT_STORE)


def load_registry(path: str | Path | None = None) -> list[Program]:
    """Load all program records. Missing/empty store -> []. Unknown keys are ignored."""
    p = _store_path(path)
    if not p.is_file():
        return []
    with _STORE_LOCK:
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
    """Atomically replace the registry so readers never observe a partial JSON write."""
    p = _store_path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps([asdict(x) for x in programs], indent=2)
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    with _STORE_LOCK:
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, p)


def upsert(program: Program, path: str | Path | None = None) -> list[Program]:
    """Add or replace a program by handle, persist, and return the new registry."""
    with _STORE_LOCK:
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
    """Expand active programs into EV-rankable targets.

    When a source provides explicit per-asset bounty eligibility, only those assets enter the
    profit queue. Sources that cannot provide that distinction retain the legacy fallback to
    all submission-eligible targets.
    """
    from .auto_hunt import HuntTarget

    progs = programs if programs is not None else load_registry(path)
    out: list[HuntTarget] = []
    for pr in progs:
        if not pr.active:
            continue
        assets = pr.bounty_eligible_targets or pr.targets
        for asset in (assets or [""]):
            if not asset:
                continue
            out.append(HuntTarget(
                repository=asset, handle=pr.handle, reward_ceiling=pr.reward_ceiling,
                findability=pr.findability, subpath=pr.subpath, kind=pr.kind,
                saturation=pr.saturation))
    return out
