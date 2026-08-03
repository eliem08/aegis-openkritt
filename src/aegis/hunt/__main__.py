"""Run the automatic hunter:  python -m aegis.hunt

Configuration (environment; a local .env is loaded):
  AEGIS_OPENKRITT_URL     open·kritt backend (required)
  HACKERONE_API_USERNAME  HackerOne Hacker-API creds (required)
  HACKERONE_API_TOKEN
  AEGIS_HUNT_MODEL        primary model id for scans, e.g. claude-opus-5 (required to launch)
  AEGIS_HUNT_FALLBACKS    comma-separated fallback model ids, tried in order if the
                          primary is unavailable (default: auto-derived from the catalog)
  AEGIS_HUNT_ARM=1        ARM it — actually launch scans. Unset/0 = dry-run (plan only)
  AEGIS_HUNT_HANDLES      comma-separated program handles (default: all authorized)
  AEGIS_HUNT_INTERVAL     seconds between cycles (default 3600)
  AEGIS_HUNT_MAX_PROGRAMS per-cycle program cap (default 3)
  AEGIS_HUNT_MAX_REPOS    per-program repo cap (default 3)
  AEGIS_HUNT_INSPECT_LIMIT programs to inspect when auto-selecting (default 20)
  AEGIS_HUNT_CYCLES       stop after N cycles (default: run until interrupted)
  AEGIS_LEARN_DB          persist what's learned (default in-memory)

It never exploits and never submits; a human reviews the console and submits.
"""

from __future__ import annotations

import os
import sys

from ..api.config import ControlPlaneConfig
from ..env import load_dotenv
from ..learn import OutcomeStore, SubmissionLedger
from .orchestrator import HuntConfig, HuntOrchestrator


def _int(name, default):
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def main() -> int:
    load_dotenv()
    config = ControlPlaneConfig.from_env()

    ok = config.build_openkritt_client()
    if ok is None:
        print("error: set AEGIS_OPENKRITT_URL to a running open·kritt backend.", file=sys.stderr)
        return 2
    try:
        from ..ingest.hackerone import HackerOneAuthError, HackerOneClient
        h1 = HackerOneClient.from_env()
    except HackerOneAuthError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    armed = (os.environ.get("AEGIS_HUNT_ARM", "").strip() in ("1", "true", "yes"))
    model = os.environ.get("AEGIS_HUNT_MODEL", "").strip()
    if armed and not model:
        print("error: AEGIS_HUNT_MODEL is required to launch scans (or leave unarmed for a dry-run).",
              file=sys.stderr)
        return 2

    handles = tuple(h.strip() for h in os.environ.get("AEGIS_HUNT_HANDLES", "").split(",") if h.strip())
    fallbacks = tuple(m.strip() for m in os.environ.get("AEGIS_HUNT_FALLBACKS", "").split(",") if m.strip())
    cfg = HuntConfig(
        model=model, fallback_models=fallbacks, only_handles=handles, dry_run=not armed,
        max_programs=_int("AEGIS_HUNT_MAX_PROGRAMS", 3),
        max_repos_per_program=_int("AEGIS_HUNT_MAX_REPOS", 3),
        inspect_limit=_int("AEGIS_HUNT_INSPECT_LIMIT", 20),
        require_bounty=os.environ.get("AEGIS_HUNT_REQUIRE_BOUNTY", "1").strip() not in ("0", "false", "no"),
        interval_seconds=float(_int("AEGIS_HUNT_INTERVAL", 3600)))
    cycles = _int("AEGIS_HUNT_CYCLES", 0) or None

    outcomes = OutcomeStore(config.learn_db_path)
    ledger = SubmissionLedger(config.learn_db_path)
    hunter = HuntOrchestrator(h1, ok, outcomes, ledger, config=cfg)

    mode = "ARMED (launching scans)" if armed else "DRY-RUN (planning only; set AEGIS_HUNT_ARM=1 to launch)"
    print(f"aegis hunter - {mode}; interval {cfg.interval_seconds:.0f}s; "
          f"caps {cfg.max_programs} programs x {cfg.max_repos_per_program} repos")
    try:
        for i, report in enumerate(hunter.run(cycles=cycles), start=1):
            print(f"[cycle {i}] {report.summary()}")
    except KeyboardInterrupt:
        print("stopped.")
    finally:
        ok.close()
        h1.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
