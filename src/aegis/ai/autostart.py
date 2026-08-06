"""Auto-start a hunt when the service boots — so launching Aegis *is* the whole pipeline.

The operator shouldn't have to add target links, POST a ranking, or run curl. With
AEGIS_AUTOSTART=1, on startup the app:

  1. optionally refreshes the program registry from the public feeds (AEGIS_AUTOSTART_IMPORT=1),
  2. picks targets — a ranking file if AEGIS_AUTOSTART_RANKING points at one, else the
     top-yield in-scope repos from selection.score_programs over the registry,
  3. launches a background (continuous by default) autohunt that feeds the dashboard.

The operator then just watches the dashboard and submits what clears the hostile-triager.
Everything downstream is unchanged: candidates only, human-gated submission, no live attacks.
Fully gated and wrapped — if anything is missing (no registry, no targets) it no-ops quietly
and the service still comes up normally.
"""

from __future__ import annotations

import os
import threading
import uuid
from pathlib import Path


def _on(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _targets():
    """Return the HuntTargets to auto-hunt, honoring AEGIS_AUTOSTART_RANKING or falling back
    to the yield-ranked registry."""
    ranking = os.environ.get("AEGIS_AUTOSTART_RANKING", "").strip()
    if ranking and Path(ranking).is_file():
        from .auto_hunt_run import build_targets_from_ranking
        return build_targets_from_ranking(ranking)
    from .registry import load_registry
    from .selection import score_programs
    n = int(os.environ.get("AEGIS_AUTOSTART_TARGETS", "8") or 8)
    ranked = score_programs(load_registry())
    return [s.target for s in ranked if getattr(s.target, "repository", "")][:n]


def maybe_autostart(app) -> None:
    """Kick off the auto-hunt in a daemon thread if AEGIS_AUTOSTART is on and nothing is
    already running. Never raises — startup must not be blocked by hunt setup."""
    if not _on("AEGIS_AUTOSTART"):
        return

    def _boot():
        try:
            if _on("AEGIS_AUTOSTART_IMPORT"):
                try:
                    from .program_sources import import_programs
                    import_programs()
                except Exception:
                    pass
            if _on("AEGIS_AUTOSTART_MONITOR"):
                # diff feeds vs registry so paused programs are marked inactive (skipped by
                # selection) and new ones get picked up before we rank.
                try:
                    from .program_monitor import monitor
                    monitor()
                except Exception:
                    pass
                # newly disclosed public reports (Bugcrowd), filtered + estimated.
                try:
                    from .disclosed_reports import collect
                    collect()
                except Exception:
                    pass
                # enrich the registry so selection can rank by money + maturity: real reward
                # from disclosed payouts, crowding, labeled priors (+ GitHub age if opted in).
                try:
                    from .program_enrich import enrich
                    enrich(use_github=_on("AEGIS_AUTOSTART_GITHUB_AGE"))
                except Exception:
                    pass
            jobs = getattr(app.state, "autohunt_jobs", None)
            if jobs is None:
                jobs = app.state.autohunt_jobs = {}
            if any(j.get("status") == "running" for j in jobs.values()):
                return                                   # a hunt is already live; don't stack
            targets = _targets()
            if not targets:
                return
            from aegis.api.routers.ui import _run_autohunt
            from .auto_hunt import AutoHuntConfig
            config = AutoHuntConfig(
                max_targets=int(os.environ.get("AEGIS_AUTOSTART_TARGETS", "8") or 8),
                samples=int(os.environ.get("AEGIS_AUTOSTART_SAMPLES", "2") or 2),
            )
            continuous = not _on("AEGIS_AUTOSTART_ONCE")   # continuous by default
            report_root = str(Path(os.environ.get("AEGIS_REPORT_DIR", "reports")).resolve())
            job_id = uuid.uuid4().hex[:12]
            jobs[job_id] = {"id": job_id, "status": "queued", "events": [],
                            "continuous": continuous, "targets": len(targets),
                            "confirmed_total": 0, "summary": None, "stop": False,
                            "autostarted": True}
            threading.Thread(
                target=_run_autohunt,
                args=(app, job_id, targets, config, report_root),
                kwargs={"continuous": continuous,
                        "interval": float(os.environ.get("AEGIS_AUTOSTART_INTERVAL", "30") or 30)},
                daemon=True, name=f"aegis-autostart-{job_id}").start()
        except Exception:
            return                                       # boot must never crash on autostart

    # run setup off the startup path (import/ranking can touch the network)
    threading.Thread(target=_boot, daemon=True, name="aegis-autostart-boot").start()
