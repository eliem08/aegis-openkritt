"""Aegis operator command line."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis")
    commands = parser.add_subparsers(dest="command", required=True)
    from aegis.effectiveness.cli import add_effectiveness_parser

    add_effectiveness_parser(commands)
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
        command.add_argument("--parent-dry-run-id")
        if name == "live-canary":
            command.add_argument("--canary-url")
            command.add_argument("--method", choices=("GET", "HEAD", "OPTIONS"))
            command.add_argument("--execute", action="store_true")
            command.add_argument("--revalidation-snapshot")
            command.add_argument("--health-report")
    args = parser.parse_args(argv)
    if args.command == "production" and args.production_command == "health":
        from aegis.production.health import main as health_main

        health_args = ["--json", args.json_path] if args.json_path else []
        return health_main(health_args)
    if args.command == "production" and args.production_command == "operator":
        return _operator(args)
    if args.command == "effectiveness":
        from aegis.effectiveness.cli import run_effectiveness

        return run_effectiveness(args)
    parser.error("unsupported command")
    return 2


def _operator(args) -> int:
    from aegis.ingest.source import ProgramSnapshot
    from aegis.policy.signing import Ed25519Signer
    from aegis.production.operator_manifest import (
        ImmutableRunStore,
        RunBudgets,
        RunMode,
        RunStatus,
    )
    from aegis.production.operator_workflow import (
        compile_dry_run,
        compile_live_canary,
        execute_live_canary,
        prepare_operator_run,
        resume_operator_run,
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
        parent_dry_run_id=args.parent_dry_run_id,
    )
    missions = (
        compile_dry_run(prepared, store) if mode is RunMode.DRY_RUN
        else compile_live_canary(
            prepared, store, canary_url=args.canary_url, method=args.method,
        )
    )
    if mode is RunMode.LIVE_CANARY and args.execute:
        if not all((args.canary_url, args.method, args.revalidation_snapshot, args.health_report)):
            raise SystemExit(
                "--execute requires --canary-url, --method, --revalidation-snapshot, and --health-report"
            )
        from aegis.production.live_canary import (
            build_supervised_runtime,
            require_fresh_ready_health,
        )

        health = require_fresh_ready_health(args.health_report)
        store.append_event(prepared.manifest.run_id, "health_verified", RunStatus.RUNNING, {
            "observed_at": health["observed_at"], "ready": True,
        })
        current = ProgramSnapshot.model_validate_json(
            Path(args.revalidation_snapshot).read_text(encoding="utf-8")
        )
        prepared = resume_operator_run(
            store, prepared.manifest.run_id, refreshed_snapshot=current,
            authorization_verifier=signer.verifier(),
        )
        egress_url = os.environ.get("AEGIS_EGRESS_URL", "").strip()
        egress_key_file = os.environ.get("AEGIS_EGRESS_SIGNING_KEY_FILE", "").strip()
        grant_key_file = os.environ.get("AEGIS_GRANT_SIGNING_KEY_FILE", "").strip()
        if not all((egress_url, egress_key_file, grant_key_file)):
            raise SystemExit(
                "AEGIS_EGRESS_URL, AEGIS_EGRESS_SIGNING_KEY_FILE, and "
                "AEGIS_GRANT_SIGNING_KEY_FILE are required"
            )
        run_dir = Path(args.runs_dir) / prepared.manifest.run_id
        runtime, grant_verifier, availability = build_supervised_runtime(
            egress_endpoint=egress_url,
            egress_signing_key_file=egress_key_file,
            grant_signing_key_file=grant_key_file,
            mission_state_path=str(run_dir / "mission-state.db"),
            run_id=prepared.manifest.run_id,
            max_requests=prepared.manifest.budgets.max_requests,
        )
        result = execute_live_canary(
            prepared, missions[0], store=store, runtime=runtime,
            availability=availability, authorization_verifier=signer.verifier(),
            grant_verifier=grant_verifier,
        )
        completed = result.outcome is not None
        store.append_event(
            prepared.manifest.run_id,
            "run_finalized",
            RunStatus.COMPLETED if completed else RunStatus.FAILED,
            {
            "execution_performed": result.outcome is not None,
            "state_changes": 0,
            },
        )
        print(json.dumps({
            "run_id": prepared.manifest.run_id,
            "scope_digest": prepared.manifest.scope_digest,
            "mission_ids": [missions[0].mission_id],
            "execution_performed": result.outcome is not None,
            "disposition": result.disposition.value,
        }, indent=2))
        return 0 if result.outcome is not None else 1
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
