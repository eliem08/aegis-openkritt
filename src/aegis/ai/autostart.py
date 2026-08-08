"""Auto-start a profit-ranked hunt when the service boots.

Autostart never builds its queue from the raw registry. It consumes only targets that pass the
fresh target-authorization gate, then ranks those by projected net value. A supplied ranking file
is also filtered through the gate before it can reach the hunt loop.
"""

from __future__ import annotations

import logging
import os
import threading
import uuid
from pathlib import Path

logger = logging.getLogger("aegis.ai.autostart")


def _on(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _targets():
    """Return the highest-value targets that are authorized *right now*."""
    from .target_authorization import gate

    n = int(os.environ.get("AEGIS_AUTOSTART_TARGETS", "8") or 8)
    ranking = os.environ.get("AEGIS_AUTOSTART_RANKING", "").strip()
    if ranking and Path(ranking).is_file():
        from .auto_hunt_run import build_targets_from_ranking

        candidates = build_targets_from_ranking(ranking)
        return [t for t in candidates if gate(t.repository, persist=False).allowed][:n]

    from .auto_hunt import AutoHuntConfig
    from .profit import rank_by_net_profit
    from .target_authorization import authorized_targets

    candidates = authorized_targets()
    ranked = rank_by_net_profit(candidates, AutoHuntConfig())
    return [target for target, estimate in ranked if estimate.net_ev > 0][:n]


def maybe_autostart(app) -> None:
    """Kick off the auto-hunt if enabled; setup failures never crash API startup."""
    if not _on("AEGIS_AUTOSTART"):
        return

    def _boot():
        try:
            if _on("AEGIS_AUTOSTART_IMPORT"):
                try:
                    from .program_sources import import_programs
                    import_programs()
                except Exception:
                    logger.exception("program import failed during autostart")
            if _on("AEGIS_AUTOSTART_MONITOR"):
                try:
                    from .program_monitor import monitor
                    monitor()
                except Exception:
                    logger.exception("program monitor failed during autostart")
                try:
                    from .disclosed_reports import collect
                    collect()
                except Exception:
                    logger.exception("disclosed-report refresh failed during autostart")
                try:
                    from .program_enrich import enrich
                    enrich(use_github=_on("AEGIS_AUTOSTART_GITHUB_AGE"))
                except Exception:
                    logger.exception("program enrichment failed during autostart")
            if _on("AEGIS_AUTOSTART_CARPET"):
                try:
                    from .carpet_sweep import run_forever
                    threading.Thread(target=run_forever, daemon=True,
                                     name="aegis-carpet").start()
                except Exception:
                    logger.exception("carpet sweep failed to start")
            jobs = getattr(app.state, "autohunt_jobs", None)
            if jobs is None:
                jobs = app.state.autohunt_jobs = {}
            if any(j.get("status") == "running" for j in jobs.values()):
                return
            targets = _targets()
            if not targets:
                logger.warning("autostart found no positive-net-EV authorized targets")
                return
            from aegis.api.routers.ui import _run_autohunt
            from .auto_hunt import AutoHuntConfig

            config = AutoHuntConfig(
                max_targets=int(os.environ.get("AEGIS_AUTOSTART_TARGETS", "8") or 8),
                samples=int(os.environ.get("AEGIS_AUTOSTART_SAMPLES", "2") or 2),
                min_net_ev=float(os.environ.get("AEGIS_AUTOSTART_MIN_NET_EV", "0") or 0),
                max_projected_spend_usd=float(
                    os.environ.get("AEGIS_AUTOSTART_MAX_SPEND_USD", "0") or 0
                ),
            )
            continuous = not _on("AEGIS_AUTOSTART_ONCE")
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
            logger.exception("autostart boot failed")

    threading.Thread(target=_boot, daemon=True, name="aegis-autostart-boot").start()
