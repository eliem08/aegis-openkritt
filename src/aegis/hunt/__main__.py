"""Run the automatic three-pass hunter with dry-run as the safe default.

Core environment variables:
  AEGIS_OPENKRITT_URL              open·kritt backend (required)
  HACKERONE_API_USERNAME/TOKEN     HackerOne Hacker API credentials
  AEGIS_HUNT_MODEL                 scan model id (required only when armed)
  AEGIS_HUNT_ARM=1                 launch selected scans; unset means plan only
  AEGIS_HUNT_HANDLES               optional comma-separated program handles
  AEGIS_HUNT_MAX_PROGRAMS          discovery program cap (default 3)
  AEGIS_HUNT_MAX_REPOS             discovery repo cap per program (default 3)
  AEGIS_HUNT_PORTFOLIO_CAPACITY    verification selections per cycle (0 = discovered)
  AEGIS_HUNT_EXPECTED_BOUNTIES_JSON explicit program-to-USD map, for example
                                    {"program":"750"}; missing amounts stay missing
  AEGIS_HUNT_EXPLORATION_FRACTION  capacity reserved for uncertainty (default 0.2)
  AEGIS_HUNT_VERIFY_MODEL          two-stage: promote hot findings to this model (e.g. Opus)
  AEGIS_HUNT_DEEPSEEK_FALLBACK=1   append deepseek/deepseek-chat via OpenRouter as a cheap
                                    last-resort fallback model (needs OPENROUTER_API_KEY
                                    configured in open·kritt; open·kritt has no native
                                    DeepSeek provider slot, so this only works via OpenRouter)

It never exploits and never submits; a human reviews the console and submits.
"""

from __future__ import annotations

import json
import os
import sys
from decimal import Decimal, InvalidOperation

from ..api.config import ControlPlaneConfig
from ..env import load_dotenv
from ..learn import OutcomeStore, SubmissionLedger
from .orchestrator import HuntConfig, HuntOrchestrator


def _int(name, default):
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _decimal(name: str, default: str) -> Decimal:
    try:
        value = Decimal(os.environ.get(name, "") or default)
    except InvalidOperation as exc:
        raise ValueError(f"{name} must be a decimal number") from exc
    if value < 0:
        raise ValueError(f"{name} cannot be negative")
    return value


def _parse_expected_bounties(raw: str) -> dict[str, Decimal]:
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("AEGIS_HUNT_EXPECTED_BOUNTIES_JSON must be valid JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("AEGIS_HUNT_EXPECTED_BOUNTIES_JSON must be an object")
    result = {}
    for handle, amount in data.items():
        name = str(handle).strip()
        try:
            value = Decimal(str(amount))
        except InvalidOperation as exc:
            raise ValueError(f"invalid expected bounty for {name or 'empty handle'}") from exc
        if not name or value < 0:
            raise ValueError("expected bounty handles must be non-empty and amounts non-negative")
        result[name] = value
    return result


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

    armed = os.environ.get("AEGIS_HUNT_ARM", "").strip() in ("1", "true", "yes")
    model = os.environ.get("AEGIS_HUNT_MODEL", "").strip()
    if armed and not model:
        print(
            "error: AEGIS_HUNT_MODEL is required to launch scans "
            "(or leave unarmed for a dry-run).",
            file=sys.stderr,
        )
        return 2

    handles = tuple(
        item.strip() for item in os.environ.get("AEGIS_HUNT_HANDLES", "").split(",")
        if item.strip()
    )
    fallbacks = tuple(
        item.strip() for item in os.environ.get("AEGIS_HUNT_FALLBACKS", "").split(",")
        if item.strip()
    )
    try:
        cfg = HuntConfig(
            model=model,
            fallback_models=fallbacks,
            only_handles=handles,
            dry_run=not armed,
            max_programs=_int("AEGIS_HUNT_MAX_PROGRAMS", 3),
            max_repos_per_program=_int("AEGIS_HUNT_MAX_REPOS", 3),
            inspect_limit=_int("AEGIS_HUNT_INSPECT_LIMIT", 20),
            require_bounty=os.environ.get("AEGIS_HUNT_REQUIRE_BOUNTY", "1").strip()
            not in ("0", "false", "no"),
            workflow_id=os.environ.get("AEGIS_HUNT_WORKFLOW_ID", "").strip(),
            post_script_id=os.environ.get("AEGIS_HUNT_POST_SCRIPT_ID", "").strip(),
            verify_model=os.environ.get("AEGIS_HUNT_VERIFY_MODEL", "").strip(),
            use_deepseek_fallback=os.environ.get("AEGIS_HUNT_DEEPSEEK_FALLBACK", "").strip()
            in ("1", "true", "yes"),
            verify_thinking_effort=os.environ.get("AEGIS_HUNT_VERIFY_EFFORT", "high").strip(),
            verify_threshold=float(os.environ.get("AEGIS_HUNT_VERIFY_THRESHOLD", "0.35")),
            interval_seconds=float(_int("AEGIS_HUNT_INTERVAL", 3600)),
            portfolio_capacity=_int("AEGIS_HUNT_PORTFOLIO_CAPACITY", 0),
            exploration_fraction=float(
                os.environ.get("AEGIS_HUNT_EXPLORATION_FRACTION", "0.2")
            ),
            expected_bounties=_parse_expected_bounties(
                os.environ.get("AEGIS_HUNT_EXPECTED_BOUNTIES_JSON", "")
            ),
            base_valid_probability=float(
                os.environ.get("AEGIS_HUNT_VALID_PROBABILITY", "0.5")
            ),
            base_acceptance_probability=float(
                os.environ.get("AEGIS_HUNT_ACCEPTANCE_PROBABILITY", "0.5")
            ),
            estimated_model_cost=_decimal("AEGIS_HUNT_MODEL_COST", "0.02"),
            estimated_scanner_cost=_decimal("AEGIS_HUNT_SCANNER_COST", "0.05"),
            estimated_verification_time_cost=_decimal(
                "AEGIS_HUNT_VERIFICATION_TIME_COST", "0.50"
            ),
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    cycles = _int("AEGIS_HUNT_CYCLES", 0) or None

    outcomes = OutcomeStore(config.learn_db_path)
    ledger = SubmissionLedger(config.learn_db_path)
    hunter = HuntOrchestrator(h1, ok, outcomes, ledger, config=cfg)

    mode = "ARMED (launching selected scans)" if armed else "DRY-RUN (planning only)"
    print(
        f"aegis hunter - {mode}; interval {cfg.interval_seconds:.0f}s; "
        f"discovery caps {cfg.max_programs} programs x {cfg.max_repos_per_program} repos; "
        f"portfolio capacity {cfg.portfolio_capacity or 'all discovered'}"
    )
    try:
        for index, report in enumerate(hunter.run(cycles=cycles), start=1):
            print(f"[cycle {index}] {report.summary()}")
    except KeyboardInterrupt:
        print("stopped.")
    finally:
        ok.close()
        h1.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
