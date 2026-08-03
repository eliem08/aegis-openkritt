"""Automatic hunting — run the whole pipeline on a loop.

One ``cycle`` does the full pass: pick authorized HackerOne programs, launch
open·kritt scans on their in-scope code repos, collect the findings into the review
console (ranked by everything learned so far), and fold new HackerOne report
outcomes back into the learning loop. ``run`` repeats it on an interval.

What it deliberately does NOT do — the boundaries that make this safe to leave
running:

* **Never exploits, never submits.** It only reads HackerOne, launches scans on
  authorized targets, reads back findings, and reads report states. A human still
  reviews the console and submits reports.
* **Scope-gated.** A program is only scanned if its policy permits automated **and**
  AI tooling and it has in-scope *source-code* repos (``repos_in_scope``). Everything
  else is skipped, with the reason recorded.
* **Dry-run by default.** Unless explicitly armed (``dry_run=False``) it plans what
  it *would* scan and launches nothing — so it cannot surprise-launch.
* **Capped.** ``max_programs`` / ``max_repos_per_program`` bound each cycle.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from aegis.integrations.repo_pipeline import (
    console_for_scans,
    run_repo_pipeline,
)
from aegis.learn import Calibration, sync_hackerone_outcomes
from aegis.report import build_console


@dataclass
class HuntConfig:
    model: str = ""
    only_handles: tuple[str, ...] = ()      # empty -> discover via list_programs()
    max_programs: int = 3
    max_repos_per_program: int = 3
    interval_seconds: float = 3600.0
    dry_run: bool = True                     # SAFE DEFAULT: plan, launch nothing


@dataclass
class HuntReport:
    dry_run: bool = True
    programs: list = field(default_factory=list)   # PipelineResult per program
    launched_scans: list = field(default_factory=list)
    console: dict = field(default_factory=dict)
    sync: object = None                             # SyncResult

    def summary(self) -> dict:
        launched = sum(len([l for l in p.launches if l.ok]) for p in self.programs)
        gated = [p.handle for p in self.programs if p.gated]
        return {
            "dry_run": self.dry_run,
            "programs_considered": len(self.programs),
            "programs_gated_out": gated,
            "repos_in_scope": sum(len(p.repos) for p in self.programs),
            "scans_launched_this_cycle": launched,
            "scans_tracked": len(self.launched_scans),
            "findings": (self.console or {}).get("totals", {}).get("candidates", 0),
            "outcomes_synced": getattr(self.sync, "recorded", 0),
        }


class HuntOrchestrator:
    def __init__(self, h1_client, ok_client, outcomes, ledger, *, config: HuntConfig):
        self._h1 = h1_client
        self._ok = ok_client
        self._outcomes = outcomes
        self._ledger = ledger
        self._cfg = config
        self._tracked: set[str] = set()      # scan ids launched across cycles

    def _handles(self) -> list[str]:
        if self._cfg.only_handles:
            return list(self._cfg.only_handles)
        handles = []
        for p in self._h1.list_programs():
            attrs = p.get("attributes") or {} if isinstance(p, dict) else {}
            h = attrs.get("handle") or (p.get("id") if isinstance(p, dict) else None)
            if h:
                handles.append(h)
        return handles

    def cycle(self) -> HuntReport:
        cfg = self._cfg
        cal = Calibration.from_outcomes(self._outcomes.all())

        programs = []
        for handle in self._handles()[: cfg.max_programs]:
            result = run_repo_pipeline(
                self._h1, self._ok, handle, model=cfg.model,
                launch=not cfg.dry_run, max_repos=cfg.max_repos_per_program)
            programs.append(result)
            for launch in result.launches:
                if launch.scan_id:
                    self._tracked.add(launch.scan_id)

        console = (console_for_scans(self._ok, sorted(self._tracked), calibration=cal)
                   if self._tracked else build_console([], calibration=cal))
        # Read-only: fold any newly-decisive report outcomes back into the loop.
        sync = sync_hackerone_outcomes(self._h1, self._ledger, self._outcomes)

        return HuntReport(dry_run=cfg.dry_run, programs=programs,
                          launched_scans=sorted(self._tracked), console=console, sync=sync)

    def run(self, *, cycles: int | None = None, sleep=time.sleep):
        """Yield a HuntReport per cycle, sleeping ``interval_seconds`` between them.

        ``cycles=None`` runs until interrupted; ``cycles=1`` is a single pass.
        """
        n = 0
        while cycles is None or n < cycles:
            yield self.cycle()
            n += 1
            if cycles is not None and n >= cycles:
                break
            sleep(self._cfg.interval_seconds)
