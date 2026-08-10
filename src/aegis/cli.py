"""Aegis operator command line."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis")
    commands = parser.add_subparsers(dest="command", required=True)
    production = commands.add_parser("production")
    production_commands = production.add_subparsers(dest="production_command", required=True)
    health = production_commands.add_parser("health")
    health.add_argument("--json", dest="json_path")
    operator = production_commands.add_parser("operator")
    operator_commands = operator.add_subparsers(dest="operator_command", required=True)
    for name in ("dry-run", "live-canary"):
        command = operator_commands.add_parser(name)
        command.add_argument("--snapshot", required=True)
        command.add_argument("--program", required=True)
        command.add_argument("--asset", action="append", required=True)
        command.add_argument("--operator-id", required=True)
        command.add_argument("--runs-dir", default="reports/operator-runs")
        command.add_argument("--identity-ref", action="append", default=[])
        command.add_argument("--max-requests", type=int, required=True)
        command.add_argument("--requests-per-second", type=float, required=True)
        command.add_argument("--max-cost-usd", type=float, required=True)
        command.add_argument("--confirm-selection", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "production" and args.production_command == "health":
        from aegis.production.health import main as health_main

        health_args = ["--json", args.json_path] if args.json_path else []
        return health_main(health_args)
    if args.command == "production" and args.production_command == "operator":
        return _operator(args)
    parser.error("unsupported command")
    return 2


def _operator(args) -> int:
    from aegis.ingest.source import ProgramSnapshot
    from aegis.policy.signing import Ed25519Signer
    from aegis.production.operator_manifest import ImmutableRunStore, RunBudgets, RunMode
    from aegis.production.operator_workflow import (
        compile_dry_run,
        compile_live_canary,
        prepare_operator_run,
    )

    document = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
    snapshots = document if isinstance(document, list) else [document]
    matches = [ProgramSnapshot.model_validate(item) for item in snapshots
               if isinstance(item, dict) and item.get("rules", {}).get("handle") == args.program]
    if len(matches) != 1:
        raise SystemExit("snapshot must contain exactly one selected program")
    snapshot = matches[0]
    selection = {
        "program": snapshot.rules.handle,
        "source": snapshot.source,
        "source_hash": snapshot.source_hash,
        "retrieved_at": snapshot.retrieved_at.isoformat(),
        "authorization_expires_at": snapshot.authorization_expires_at.isoformat(),
        "selected_assets": args.asset,
        "automation_allowed": snapshot.rules.automation_allowed,
        "ai_allowed": snapshot.rules.ai_allowed,
        "program_rate_limit_rps": snapshot.rules.rate_limit_rps,
    }
    print(json.dumps({"operator_selection": selection}, indent=2))
    if not args.confirm_selection:
        print("selection not confirmed; no authorization or run manifest was created")
        return 2
    key_file = os.environ.get("AEGIS_OPERATOR_SIGNING_KEY_FILE", "").strip()
    key_id = os.environ.get("AEGIS_OPERATOR_SIGNING_KEY_ID", "").strip()
    if not key_file or not key_id:
        raise SystemExit("AEGIS_OPERATOR_SIGNING_KEY_FILE and AEGIS_OPERATOR_SIGNING_KEY_ID are required")
    signer = Ed25519Signer(Path(key_file).read_text(encoding="utf-8").strip(), key_id)
    mode = RunMode.DRY_RUN if args.operator_command == "dry-run" else RunMode.LIVE_CANARY
    store = ImmutableRunStore(args.runs_dir)
    prepared = prepare_operator_run(
        snapshot, selected_assets=tuple(args.asset), operator_id=args.operator_id,
        mode=mode,
        budgets=RunBudgets(args.max_requests, args.requests_per_second, args.max_cost_usd),
        signer=signer, store=store, controlled_identity_refs=tuple(args.identity_ref),
    )
    missions = (
        compile_dry_run(prepared, store) if mode is RunMode.DRY_RUN
        else compile_live_canary(prepared, store)
    )
    print(json.dumps({
        "run_id": prepared.manifest.run_id,
        "scope_digest": prepared.manifest.scope_digest,
        "mission_ids": [mission.mission_id for mission in missions],
        "execution_performed": False,
        "next_action": "invoke supervised canonical executor" if mode is RunMode.LIVE_CANARY else "human review",
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
