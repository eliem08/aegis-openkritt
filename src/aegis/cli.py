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
    campaign = operator_commands.add_parser("campaign")
    campaign.add_argument("--snapshot", required=True)
    campaign.add_argument("--program", required=True)
    campaign.add_argument("--campaign-manifest", required=True)
    campaign.add_argument("--runs-dir", default="reports/operator-runs")
    campaign.add_argument("--confirm-selection", action="store_true")
    campaign.add_argument("--execute", action="store_true")
    campaign.add_argument("--revalidation-snapshot")
    campaign.add_argument("--health-report")
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
    if args.operator_command == "campaign":
        return _campaign_operator(args)
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


def _campaign_operator(args) -> int:
    """Prepare or execute an operator-supplied campaign manifest fail closed."""
    from aegis.ai.jarvis.asset_execution_ticket import CapabilityAvailability
    from aegis.ai.jarvis.deterministic_hunter_executors import (
        DeterministicHunterExecutorProvider,
    )
    from aegis.ai.jarvis.hunter_techniques import HunterTechnique
    from aegis.ai.jarvis.mission_scheduler import MissionScheduler
    from aegis.ai.jarvis.state_store import JarvisStateStore
    from aegis.ai.jarvis.universal_runtime import UniversalMissionRuntime
    from aegis.ingest.source import ProgramSnapshot
    from aegis.policy.signing import Ed25519Signer, HmacSignatureVerifier
    from aegis.production.campaign_runner import (
        BackendCapability,
        CampaignRequest,
        OperatorTechniqueApproval,
        PermissionEffect,
        PolicyEvidence,
        TechniqueRequest,
        TypedTechniquePermission,
        execute_campaign,
        prepare_campaign,
    )
    from aegis.production.live_canary import require_fresh_ready_health
    from aegis.production.operator_manifest import ImmutableRunStore, RunBudgets, RunStatus

    snapshot_document = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
    snapshots = snapshot_document if isinstance(snapshot_document, list) else [snapshot_document]
    matches = [ProgramSnapshot.model_validate(item) for item in snapshots
               if isinstance(item, dict) and item.get("rules", {}).get("handle") == args.program]
    if len(matches) != 1:
        raise SystemExit("snapshot must contain exactly one selected program")
    snapshot = matches[0]
    document = json.loads(Path(args.campaign_manifest).read_text(encoding="utf-8"))
    budget = RunBudgets(**dict(document.get("budgets") or {}))
    techniques = tuple(TechniqueRequest(
        HunterTechnique(item["technique"]), str(item["asset"]),
        str(item.get("context") or "default"),
        tuple(str(value) for value in item.get("identity_refs") or ()),
        dict(item.get("execution_inputs") or {}),
    ) for item in document.get("techniques") or ())
    request = CampaignRequest(
        str(document.get("campaign_id") or ""),
        str(document.get("operator_id") or ""), techniques, budget,
    )
    permissions = tuple(TypedTechniquePermission(
        HunterTechnique(item["technique"]), str(item["asset"]),
        str(item.get("context") or "default"), PermissionEffect(item["effect"]),
        str(item["policy_action"]), dict(item.get("typed_constraints") or {}),
        PolicyEvidence(**dict(item["evidence"])),
    ) for item in document.get("permissions") or ())
    approvals = tuple(OperatorTechniqueApproval(
        str(item["approval_id"]), str(item["campaign_id"]),
        HunterTechnique(item["technique"]), str(item["asset"]),
        str(item.get("context") or "default"),
        tuple(str(value) for value in item.get("identity_refs") or ()),
        str(item["valid_from"]), str(item["valid_until"]),
        str(item["key_id"]), str(item["signature"]), int(item.get("version", 1)),
    ) for item in document.get("approvals") or ())
    backends = tuple(BackendCapability(
        str(item["worker_capability"]), str(item["backend"]),
        str(item["backend_version"]), item["available"], item["safe"],
        tuple(str(value) for value in item.get("enforceable_constraints") or ()),
        tuple(str(value) for value in item.get("satisfied_prerequisites") or ()),
        str(item.get("unavailable_reason") or ""),
    ) for item in document.get("backends") or ())
    print(json.dumps({"operator_campaign_selection": {
        "campaign_id": request.campaign_id,
        "program": snapshot.rules.handle,
        "source": snapshot.source,
        "source_hash": snapshot.source_hash,
        "assets": list(dict.fromkeys(item.asset for item in techniques)),
        "techniques": [item.technique.value for item in techniques],
        "budgets": document["budgets"],
    }}, indent=2))
    if not args.confirm_selection:
        print("selection not confirmed; no authorization or run manifest was created")
        return 2
    key_file = os.environ.get("AEGIS_OPERATOR_SIGNING_KEY_FILE", "").strip()
    key_id = os.environ.get("AEGIS_OPERATOR_SIGNING_KEY_ID", "").strip()
    if not key_file or not key_id:
        raise SystemExit(
            "AEGIS_OPERATOR_SIGNING_KEY_FILE and AEGIS_OPERATOR_SIGNING_KEY_ID are required"
        )
    signer = Ed25519Signer(Path(key_file).read_text(encoding="utf-8").strip(), key_id)
    store = ImmutableRunStore(args.runs_dir)
    prepared = prepare_campaign(
        snapshot, request, permissions=permissions, approvals=approvals,
        backends=backends, signer=signer, store=store,
    )
    store.append_event(
        prepared.operator_run.manifest.run_id,
        "operator_signing_key_referenced",
        RunStatus.AUTHORIZED,
        {
            "signing_key_id": key_id,
            "signing_key_path_reference": key_file,
            "private_key_persisted": False,
        },
    )
    if not args.execute:
        print(json.dumps({
            "run_id": prepared.operator_run.manifest.run_id,
            "campaign_id": request.campaign_id,
            "scope_digest": prepared.operator_run.manifest.scope_digest,
            "decisions": [item.document() for item in prepared.decisions],
            "mission_ids": [item.mission_id for item in prepared.missions],
            "execution_performed": False,
            "human_submission_required": True,
        }, indent=2))
        return 0
    if not args.revalidation_snapshot or not args.health_report:
        raise SystemExit("--execute requires --revalidation-snapshot and --health-report")
    require_fresh_ready_health(args.health_report)
    grant_file = os.environ.get("AEGIS_GRANT_SIGNING_KEY_FILE", "").strip()
    if not grant_file:
        raise SystemExit("AEGIS_GRANT_SIGNING_KEY_FILE is required")
    grant_secret = Path(grant_file).read_text(encoding="utf-8").strip()
    if len(grant_secret) < 32:
        raise SystemExit("execution grant signing key is too short")
    grant_verifier = HmacSignatureVerifier({"grant": grant_secret})
    provider = DeterministicHunterExecutorProvider(grant_verifier=grant_verifier)
    executable = set(provider.runtime_executors())
    requested_authorized = {
        item.worker_capability for item in backends if item.available and item.safe
    }
    if not requested_authorized <= executable:
        raise SystemExit(
            "CLI execution supports only registered networkless hunter backends; "
            "use the production worker assembly for scoped dynamic capabilities"
        )
    run_dir = Path(args.runs_dir) / prepared.operator_run.manifest.run_id
    runtime = UniversalMissionRuntime(
        MissionScheduler(JarvisStateStore(run_dir / "mission-state.db")),
        grant_verifier=grant_verifier, executor_providers=(provider,),
    )

    def current_snapshot() -> ProgramSnapshot:
        return ProgramSnapshot.model_validate_json(
            Path(args.revalidation_snapshot).read_text(encoding="utf-8")
        )

    results = execute_campaign(
        prepared, snapshot_provider=current_snapshot, permissions=permissions,
        approvals=approvals, backends=backends, store=store, runtime=runtime,
        availability=CapabilityAvailability(), authorization_verifier=signer.verifier(),
        grant_verifier=grant_verifier,
    )
    print(json.dumps({
        "run_id": prepared.operator_run.manifest.run_id,
        "campaign_id": request.campaign_id,
        "execution_performed": any(item.outcome is not None for item in results),
        "results": [{"disposition": item.disposition.value, "reason": item.reason}
                    for item in results],
        "final_status": store.verify(prepared.operator_run.manifest.run_id)["last_status"],
        "human_submission_required": True,
    }, indent=2))
    return 0 if all(item.outcome is not None for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
