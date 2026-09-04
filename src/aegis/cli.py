"""Aegis operator command line."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis")
    commands = parser.add_subparsers(dest="command", required=True)
    from aegis.effectiveness.cli import add_effectiveness_parser

    add_effectiveness_parser(commands)
    from aegis.products.cli import add_products_parser

    add_products_parser(commands)
    arsenal = commands.add_parser("arsenal")
    arsenal_commands = arsenal.add_subparsers(dest="arsenal_command", required=True)
    arsenal_audit = arsenal_commands.add_parser("audit")
    arsenal_audit.add_argument("--json", dest="json_path")
    arsenal_audit.add_argument("--markdown", dest="markdown_path")
    arsenal_audit.add_argument("--runs-dir", default="reports/operator-runs")
    arsenal_audit.add_argument(
        "--release-lock", default="config/arsenal-release-lock.json",
    )
    arsenal_backlog = arsenal_commands.add_parser("backlog")
    arsenal_backlog.add_argument("--json", dest="json_path", required=True)
    arsenal_backlog.add_argument("--markdown", dest="markdown_path", required=True)
    arsenal_backlog.add_argument(
        "--coverage", default="reports/arsenal/FULL_ARSENAL_COVERAGE.json",
    )
    arsenal_backlog.add_argument("--runs-dir", default="reports/operator-runs")
    arsenal_backlog.add_argument(
        "--release-lock", default="config/arsenal-release-lock.json",
    )
    arsenal_runners = arsenal_commands.add_parser("runners")
    arsenal_runners.add_argument("--json", dest="json_path")
    arsenal_runners.add_argument("--markdown", dest="markdown_path")
    arsenal_runners.add_argument("--runtime-lock-json")
    arsenal_runners.add_argument(
        "--coverage", default="reports/arsenal/FULL_ARSENAL_COVERAGE.json",
    )
    arsenal_runners.add_argument(
        "--release-lock", default="config/arsenal-release-lock.json",
    )
    arsenal_exercise = arsenal_commands.add_parser("exercise")
    exercise_selection = arsenal_exercise.add_mutually_exclusive_group(required=True)
    exercise_selection.add_argument("--capability")
    exercise_selection.add_argument("--all-fixture-tools", action="store_true")
    exercise_selection.add_argument("--runner")
    arsenal_exercise.add_argument("--runs-dir", default="reports/operator-runs")
    arsenal_exercise.add_argument("--json", dest="json_path")
    arsenal_exercise.add_argument("--markdown", dest="markdown_path")
    arsenal_exercise.add_argument("--backend-inventory-json")
    arsenal_exercise.add_argument("--backend-inventory-markdown")
    arsenal_exercise.add_argument("--tool-lock-json")
    arsenal_exercise.add_argument("--runtime-lock-json")
    arsenal_exercise.add_argument(
        "--resume", action="store_true",
        help="reuse only version-compatible coverage whose immutable evidence still verifies",
    )
    arsenal_exercise.add_argument(
        "--force", action="store_true", help="rerun even when --resume evidence is valid",
    )
    arsenal_exercise.add_argument(
        "--release-lock", default="config/arsenal-release-lock.json",
    )
    arsenal_exercise.add_argument(
        "--image-digest", default=os.environ.get("AEGIS_ARSENAL_IMAGE_DIGEST", ""),
    )
    arsenal_exercise.add_argument("--coverage-sqlite", help=argparse.SUPPRESS)
    _add_arsenal_hunt_parser(arsenal_commands)
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
    if args.command == "products":
        from aegis.products.cli import run_products

        return run_products(args)
    if args.command == "arsenal" and args.arsenal_command == "hunt":
        return _arsenal_hunt(args)
    if args.command == "arsenal" and args.arsenal_command == "assets":
        from aegis.arsenal.assets import coverage_matrix

        print(json.dumps(coverage_matrix(), indent=2, sort_keys=True))
        return 0
    if args.command == "arsenal" and args.arsenal_command == "audit":
        from aegis.arsenal.audit import build_audit, write_audit

        report = build_audit(
            runs_dir=args.runs_dir, release_lock_path=args.release_lock,
        )
        write_audit(report, json_path=args.json_path, markdown_path=args.markdown_path)
        if not args.json_path and not args.markdown_path:
            print(json.dumps(report.document(), indent=2, sort_keys=True))
        return 0
    if args.command == "arsenal" and args.arsenal_command == "backlog":
        from aegis.arsenal.audit import build_audit
        from aegis.arsenal.backend_report import build_backend_inventory
        from aegis.arsenal.backlog import build_never_executed_backlog, write_backlog

        audit = build_audit(
            runs_dir=args.runs_dir, release_lock_path=args.release_lock,
        )
        inventory = build_backend_inventory(audit)
        coverage = {}
        coverage_path = Path(args.coverage)
        if coverage_path.is_file():
            coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
        write_backlog(
            build_never_executed_backlog(inventory, coverage),
            json_path=args.json_path, markdown_path=args.markdown_path,
        )
        return 0
    if args.command == "arsenal" and args.arsenal_command == "runners":
        from aegis.arsenal.audit import build_audit
        from aegis.arsenal.backend_report import (
            build_backend_inventory,
            build_runtime_lock,
            write_json,
        )
        from aegis.arsenal.runners import render_runner_markdown, runner_readiness

        inventory = build_backend_inventory(build_audit(
            release_lock_path=args.release_lock,
        ))
        mapping: dict[str, list[str]] = {}
        executable_mapping: dict[str, list[str]] = {}
        coverage_path = Path(args.coverage)
        coverage = (
            json.loads(coverage_path.read_text(encoding="utf-8"))
            if coverage_path.is_file() else {}
        )
        never = set(coverage.get("never_executed_backend_ids", ()))
        for backend in inventory["backends"]:
            if backend.get("external"):
                mapping.setdefault(backend["runner_profile"], []).append(
                    backend["backend_runtime_id"]
                )
                if backend["backend_id"] not in never and coverage:
                    executable_mapping.setdefault(backend["runner_profile"], []).append(
                        backend["backend_runtime_id"]
                    )
        document = runner_readiness(
            backend_runtimes=mapping, executable_runtimes=executable_mapping,
        )
        if args.json_path:
            write_json(args.json_path, document)
        if args.markdown_path:
            Path(args.markdown_path).write_text(
                render_runner_markdown(document), encoding="utf-8",
            )
        if args.runtime_lock_json:
            write_json(args.runtime_lock_json, build_runtime_lock(inventory))
        if not args.json_path and not args.markdown_path and not args.runtime_lock_json:
            print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    if args.command == "arsenal" and args.arsenal_command == "exercise":
        from aegis.ai.tool_runtime import ToolRuntimeManager, ToolRuntimeStatus
        from aegis.arsenal.audit import build_audit
        from aegis.arsenal.backend_report import (
            backend_prerequisite,
            build_backend_inventory,
            build_full_coverage_report,
            build_runtime_lock,
            build_tool_lock,
            canonical_binary,
            render_backend_inventory_markdown,
            render_full_coverage_markdown,
            write_json,
        )
        from aegis.arsenal.exercise import (
            ExerciseResult,
            execute_llm_fixture,
            record_blocked_fixture,
            write_result,
        )
        from aegis.arsenal.external_fixtures import external_fixture_spec
        from aegis.arsenal.inventory import ArsenalInventoryBuilder
        from aegis.arsenal.ledger import SqliteCoverageRepository, repository_from_env
        from aegis.arsenal.models import ArsenalCoverageState
        from aegis.arsenal.resume import resumable_record
        from aegis.arsenal.tool_exercise import (
            equivalent_capability_ids,
            execute_tool_fixture,
            fixture_version_for_capability,
        )

        repository = None
        try:
            if args.coverage_sqlite:
                Path(args.coverage_sqlite).parent.mkdir(parents=True, exist_ok=True)
            repository = (
                SqliteCoverageRepository(args.coverage_sqlite)
                if args.coverage_sqlite else repository_from_env()
            )
        except Exception:
            # Runtime evidence remains canonical; the exercise records the coverage projection
            # outage explicitly instead of fabricating a successful ledger write.
            repository = None
        try:
            definitions = ArsenalInventoryBuilder().build()
            definition_by_id = {item.capability_id: item for item in definitions}
            if args.all_fixture_tools:
                fixture_capabilities = [
                    item.capability_id for item in definitions if item.fixture_executable
                ]
                projected_aliases = {
                    alias
                    for capability_id in fixture_capabilities
                    for alias in equivalent_capability_ids(capability_id)
                }
                # An alias covered by an identical real fixture is projected from that
                # execution. Recording a second WAITING row would contradict the evidence.
                capabilities = [
                    capability_id
                    for capability_id in fixture_capabilities
                    if capability_id not in projected_aliases
                ]
            elif args.runner:
                from aegis.arsenal.runners import runner_profile_for_binary

                fixture_capabilities = [
                    item for item in definitions if item.fixture_executable
                ]
                projected_aliases = {
                    alias for item in fixture_capabilities
                    for alias in equivalent_capability_ids(item.capability_id)
                }
                capabilities = [
                    item.capability_id for item in fixture_capabilities
                    if item.capability_id not in projected_aliases
                    and (
                        item.capability_id == "fixture:ai/llm-security-boundary"
                        and args.runner == "arsenal-llm"
                        or item.tool_backends
                        and runner_profile_for_binary(
                            canonical_binary(item.tool_backends[0].binary)
                        ) == args.runner
                    )
                ]
            else:
                capabilities = [args.capability]
            manager = ToolRuntimeManager(version_timeout=15.0)
            results = []
            audit_for_resume = (
                build_audit(runs_dir=args.runs_dir, release_lock_path=args.release_lock)
                if args.resume and repository is not None and not args.force else None
            )
            prior_records = repository.records() if audit_for_resume is not None else ()
            for index, capability in enumerate(capabilities, start=1):
                print(
                    f"arsenal fixture {index}/{len(capabilities)} START {capability}",
                    file=sys.stderr, flush=True,
                )
                definition = definition_by_id.get(capability)
                if definition is None:
                    raise ValueError(f"unknown arsenal capability: {capability}")
                if (
                    audit_for_resume is not None
                    and capability != "fixture:ai/llm-security-boundary"
                    and definition.tool_backends
                ):
                    backend = definition.tool_backends[0]
                    prior_runtime = manager.inspect(
                        name=backend.tool_name, binary=canonical_binary(backend.binary),
                        refresh=True,
                    )
                    prior = resumable_record(
                        prior_records, audit_for_resume.history,
                        capability_id=capability, tool_version=prior_runtime.version,
                        adapter_version=backend.adapter_version,
                        fixture_version=fixture_version_for_capability(capability),
                    )
                    if prior is not None:
                        result = ExerciseResult(
                            prior.run_id, prior.mission_id, prior.task_id, capability,
                            prior.result, "", str(prior.evidence_digest), True, False,
                            {
                                "resumed": True,
                                "covered_capability_ids": list(
                                    prior.capability_ids or (capability,)
                                ),
                                "backend_execution_id": prior.backend_execution_id,
                                "tool_version": prior.tool_version,
                                "fixture_version": prior.fixture_version,
                            },
                        )
                        results.append(result)
                        print(
                            f"arsenal fixture {index}/{len(capabilities)} RESUMED {capability}",
                            file=sys.stderr, flush=True,
                        )
                        continue
                if capability == "fixture:ai/llm-security-boundary":
                    try:
                        result = execute_llm_fixture(
                            runs_dir=args.runs_dir, coverage_repository=repository,
                        )
                    except Exception as exc:
                        result = record_blocked_fixture(
                            capability,
                            state_value=ArsenalCoverageState.BACKEND_UNHEALTHY,
                            reason=f"{type(exc).__name__}: {exc}"[:500],
                            runs_dir=args.runs_dir, coverage_repository=repository,
                        )
                    results.append(result)
                    print(
                        f"arsenal fixture {index}/{len(capabilities)} "
                        f"{results[-1].result.value} {capability}",
                        file=sys.stderr, flush=True,
                    )
                    continue
                spec = external_fixture_spec(capability)
                if (
                    definition.tool_backends
                    and (
                        capability.startswith("tool:")
                        or spec is not None
                    )
                ):
                    backend = definition.tool_backends[0]
                    tool_name = spec.tool.name if spec is not None else backend.tool_name
                    tool_binary = canonical_binary(spec.tool.binary) if spec is not None else canonical_binary(backend.binary)
                    runtime = manager.inspect(
                        name=tool_name,
                        binary=tool_binary,
                        refresh=True,
                    )
                    if runtime.status is not ToolRuntimeStatus.READY:
                        results.append(record_blocked_fixture(
                            capability,
                            state_value=(
                                ArsenalCoverageState.BACKEND_UNHEALTHY
                                if runtime.status in {
                                    ToolRuntimeStatus.STALE, ToolRuntimeStatus.QUARANTINED,
                                }
                                else ArsenalCoverageState.UNAVAILABLE
                            ),
                            reason=runtime.reason or f"{backend.binary} is unavailable",
                            runs_dir=args.runs_dir, coverage_repository=repository,
                        ))
                    else:
                        try:
                            result = execute_tool_fixture(
                                capability, runs_dir=args.runs_dir,
                                coverage_repository=repository,
                            )
                        except Exception as exc:
                            result = record_blocked_fixture(
                                capability,
                                state_value=ArsenalCoverageState.BACKEND_UNHEALTHY,
                                reason=f"{type(exc).__name__}: {exc}"[:500],
                                runs_dir=args.runs_dir,
                                coverage_repository=repository,
                            )
                        results.append(result)
                    print(
                        f"arsenal fixture {index}/{len(capabilities)} "
                        f"{results[-1].result.value} {capability}",
                        file=sys.stderr, flush=True,
                    )
                    continue
                backend = definition.tool_backends[0] if definition.tool_backends else None
                binary = canonical_binary(backend.binary) if backend else ""
                special_prerequisite = backend_prerequisite(binary)
                external = bool(binary) and not binary.startswith(("aegis-", "stdlib-"))
                runtime = manager.inspect(
                    name=backend.tool_name, binary=binary, refresh=True,
                ) if backend and external else None
                if special_prerequisite:
                    blocked_state = ArsenalCoverageState.WAITING_FOR_PREREQUISITE
                    prerequisite = special_prerequisite
                elif runtime and runtime.status is not ToolRuntimeStatus.READY:
                    blocked_state = (
                        ArsenalCoverageState.BACKEND_UNHEALTHY
                        if runtime.status in {
                            ToolRuntimeStatus.STALE, ToolRuntimeStatus.QUARANTINED,
                        }
                        else ArsenalCoverageState.UNAVAILABLE
                    )
                    prerequisite = runtime.reason or f"binary {binary!r} is unavailable"
                elif definition.fixture_provider:
                    blocked_state = ArsenalCoverageState.WAITING_FOR_PREREQUISITE
                    prerequisite = (
                        "backend is present but its deterministic positive/negative fixture "
                        "provider is not connected to the canonical executor"
                    )
                else:
                    blocked_state = ArsenalCoverageState.NOT_IMPLEMENTED
                    prerequisite = "no canonical fixture executor is implemented"
                results.append(record_blocked_fixture(
                    capability,
                    state_value=blocked_state,
                    reason=prerequisite, runs_dir=args.runs_dir,
                    coverage_repository=repository,
                ))
                print(
                    f"arsenal fixture {index}/{len(capabilities)} "
                    f"{results[-1].result.value} {capability}",
                    file=sys.stderr, flush=True,
                )
        finally:
            if repository is not None:
                repository.close()
        if args.json_path and len(results) == 1:
            write_result(results[0], args.json_path)
        elif args.json_path:
            audit = build_audit(runs_dir=args.runs_dir, release_lock_path=args.release_lock)
            inventory = build_backend_inventory(audit)
            report = build_full_coverage_report(
                audit=audit, inventory=inventory,
                results=(item.document() for item in results),
                image_digest=args.image_digest,
            )
            write_json(args.json_path, report)
            if args.markdown_path:
                Path(args.markdown_path).write_text(
                    render_full_coverage_markdown(report), encoding="utf-8",
                )
            if args.backend_inventory_json:
                write_json(args.backend_inventory_json, inventory)
            if args.backend_inventory_markdown:
                Path(args.backend_inventory_markdown).write_text(
                    render_backend_inventory_markdown(inventory), encoding="utf-8",
                )
            if args.tool_lock_json:
                write_json(
                    args.tool_lock_json,
                    build_tool_lock(inventory, image_digest=args.image_digest),
                )
            if args.runtime_lock_json:
                write_json(
                    args.runtime_lock_json,
                    build_runtime_lock(inventory, image_digest=args.image_digest),
                )
        elif args.markdown_path:
            audit = build_audit(runs_dir=args.runs_dir, release_lock_path=args.release_lock)
            inventory = build_backend_inventory(audit)
            report = build_full_coverage_report(
                audit=audit, inventory=inventory,
                results=(item.document() for item in results),
                image_digest=args.image_digest,
            )
            Path(args.markdown_path).write_text(
                render_full_coverage_markdown(report), encoding="utf-8",
            )
        else:
            print(json.dumps([item.document() for item in results], indent=2, sort_keys=True))
        return 0 if all(item.result.value == "EXECUTED_PASS" for item in results) else 1
    parser.error("unsupported command")
    return 2


def _add_arsenal_hunt_parser(arsenal_commands) -> None:
    """Register ``aegis arsenal hunt`` and ``aegis arsenal assets``.

    The scope file is required with no default. Making the operator name it every
    time is the point: a hunt that could inherit a stale allowlist is a hunt that
    can wander out of scope without anyone noticing.
    """
    arsenal_commands.add_parser(
        "assets", help="print the supported asset types and the techniques each routes to",
    )
    hunt = arsenal_commands.add_parser(
        "hunt", help="run the techniques registered for one in-scope asset",
    )
    hunt.add_argument("--asset", required=True, help="the asset identifier to hunt")
    hunt.add_argument(
        "--asset-type",
        help="asset type; inferred from the identifier when omitted "
             "(cidr, domain, wildcard, ip_address, api, aws_account, azure_account, "
             "source_code, executable, smart_contract, ai_model, other_asset)",
    )
    hunt.add_argument(
        "--scope-file", required=True,
        help="operator scope allowlist (JSON or newline-delimited; '!' marks exclusions)",
    )
    hunt.add_argument("--technique", action="append", default=[],
                      help="run only this technique (repeatable)")
    hunt.add_argument("--artifact", help="local artifact: checkout, binary, or contract source")
    hunt.add_argument("--api-spec", help="OpenAPI/Swagger document for an API asset")
    hunt.add_argument("--policy-document", action="append", default=[],
                      help="IAM/resource policy JSON to review (repeatable)")
    hunt.add_argument(
        "--identity", action="append", default=[],
        help="an already-authenticated role as label:Header=value[,Header=value]; "
             "Aegis never logs in, so you supply the session material yourself",
    )
    hunt.add_argument("--option", action="append", default=[],
                      help="lane option as key=value (repeatable)")
    hunt.add_argument("--workspace", help="directory for unpacked artifacts")
    hunt.add_argument("--requests-per-second", type=float, default=0.5)
    hunt.add_argument("--max-requests", type=int, default=200)
    hunt.add_argument("--timeout-seconds", type=float, default=15.0)
    hunt.add_argument(
        "--allow-state-change", action="store_true",
        help="permit non-GET/HEAD/OPTIONS requests; only with program authorization",
    )
    hunt.add_argument("--request-log", help="append every outbound attempt to this JSONL file")
    hunt.add_argument("--json", dest="json_path")
    hunt.add_argument("--markdown", dest="markdown_path")


def _parse_identity(raw: str):
    from aegis.arsenal.assets import Identity

    label, separator, remainder = raw.partition(":")
    if not separator or not label.strip():
        raise SystemExit(f"--identity must be label:Header=value, got {raw!r}")
    headers: dict[str, str] = {}
    for pair in remainder.split(","):
        if not pair.strip():
            continue
        name, equals, value = pair.partition("=")
        if not equals:
            raise SystemExit(f"--identity header must be Name=value, got {pair!r}")
        headers[name.strip()] = value.strip()
    if not headers:
        raise SystemExit(f"--identity {label!r} carries no headers")
    return Identity(label.strip(), headers)


def _parse_options(raw_options: list[str]) -> dict:
    options: dict = {}
    for entry in raw_options:
        key, equals, value = entry.partition("=")
        if not equals:
            raise SystemExit(f"--option must be key=value, got {entry!r}")
        key = key.strip()
        value = value.strip()
        if key in {"buckets", "containers", "vhost_candidates"}:
            options[key] = [item.strip() for item in value.split(",") if item.strip()]
        elif value.lstrip("-").isdigit():
            options[key] = int(value)
        else:
            options[key] = value
    return options


def _arsenal_hunt(args) -> int:
    from aegis.arsenal.assets import (
        HuntRefused,
        RateLimit,
        ScopeFileError,
        UnsupportedAssetType,
        load_allowlist,
        parse_asset_type,
        render_markdown,
        run_hunt,
        write_report,
    )

    try:
        allowlist = load_allowlist(args.scope_file)
    except ScopeFileError as exc:
        print(json.dumps({"error": "scope_file_invalid", "detail": str(exc)}, indent=2))
        return 2
    try:
        asset_type = parse_asset_type(args.asset_type) if args.asset_type else None
    except (UnsupportedAssetType, ValueError) as exc:
        print(json.dumps({"error": "asset_type_rejected", "detail": str(exc)}, indent=2))
        return 2

    try:
        report = run_hunt(
            asset=args.asset,
            allowlist=allowlist,
            asset_type=asset_type,
            rate_limit=RateLimit(
                requests_per_second=args.requests_per_second,
                max_requests=args.max_requests,
                timeout_seconds=args.timeout_seconds,
            ),
            allow_state_change=args.allow_state_change,
            artifact_path=args.artifact,
            specification_path=args.api_spec,
            policy_documents=args.policy_document,
            identities=[_parse_identity(item) for item in args.identity],
            workspace=args.workspace,
            options=_parse_options(args.option),
            log_path=args.request_log,
            only=args.technique,
        )
    except HuntRefused as exc:
        # The single most important failure mode: refuse loudly, do nothing.
        print(json.dumps({"error": "out_of_scope", "detail": str(exc)}, indent=2))
        return 3
    except (UnsupportedAssetType, ValueError) as exc:
        print(json.dumps({"error": "hunt_rejected", "detail": str(exc)}, indent=2))
        return 2

    if args.json_path:
        write_report(report, args.json_path)
    if args.markdown_path:
        markdown = Path(args.markdown_path)
        markdown.parent.mkdir(parents=True, exist_ok=True)
        markdown.write_text(render_markdown(report), encoding="utf-8")
    if not args.json_path and not args.markdown_path:
        print(json.dumps(report.document(), indent=2, sort_keys=True))
    return 0 if report.executed_count else 1


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
