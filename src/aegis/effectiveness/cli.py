"""Operator CLI handlers for effectiveness measurement."""

from __future__ import annotations

import json
import os
import sys
from decimal import Decimal
from pathlib import Path

from .metrics import calculate_metrics
from .models import (
    CampaignEvent,
    CampaignInput,
    CostObservation,
    OutcomeInput,
    OutcomeState,
    utc_now,
)
from .operations import daily_profitability_document, pending_review_queue
from .report import render_json, render_markdown, render_v2_json, render_v2_markdown
from .repository import (
    EffectivenessError,
    EffectivenessStorageStateError,
    open_effectiveness_repository,
)
from .service import ingest_lineage_document, record_cost_observation, record_human_outcome
from .shadow import ShadowCandidate, build_shadow_batch


def add_effectiveness_parser(commands) -> None:
    effectiveness = commands.add_parser("effectiveness")
    effectiveness_commands = effectiveness.add_subparsers(
        dest="effectiveness_command", required=True,
    )
    for name in (
        "ingest-run", "record-outcome", "amend-outcome", "record-cost", "shadow-rank",
        "campaign-create", "campaign-event", "pending", "daily", "report",
    ):
        command = effectiveness_commands.add_parser(name)
        command.add_argument("--backend", choices=("postgresql", "sqlite"))
        command.add_argument("--database")
        if name in {
            "ingest-run", "record-outcome", "amend-outcome", "record-cost", "shadow-rank",
            "campaign-create", "campaign-event",
        }:
            command.add_argument("--input", required=True)
        if name in {"record-outcome", "amend-outcome"}:
            command.add_argument("--confirm", action="store_true")
        if name in {"report", "daily"}:
            command.add_argument("--format", choices=("json", "markdown"), default="json")
            command.add_argument("--output")


def _decimal(document, name):
    return None if document.get(name) is None else Decimal(str(document[name]))


def _outcome(document) -> OutcomeInput:
    return OutcomeInput(
        subject_id=document["subject_id"], state=OutcomeState(document["state"]),
        submitted_severity=document.get("submitted_severity"),
        triaged_severity=document.get("triaged_severity"), bounty_usd=_decimal(document, "bounty_usd"),
        submitted_at=document.get("submitted_at"), triaged_at=document.get("triaged_at"),
        resolved_at=document.get("resolved_at"),
        human_review_minutes=_decimal(document, "human_review_minutes"),
        model_api_cost_usd=_decimal(document, "model_api_cost_usd"),
        compute_cost_usd=_decimal(document, "compute_cost_usd"),
        analyst_note=document.get("analyst_note"), operator_id=document["operator_id"],
        source_digest=document["source_digest"], idempotency_key=document["idempotency_key"],
        supersedes_outcome_event_id=document.get("supersedes_outcome_event_id"),
    )


def _repository(args):
    source = dict(os.environ)
    production = str(source.get("AEGIS_PRODUCTION", "")).lower() in {"1", "true", "yes", "on"}
    if production:
        from aegis.production.config import materialize_secret_environment

        source, _secret_sources = materialize_secret_environment(source)
    backend = args.backend or source.get("AEGIS_EFFECTIVENESS_BACKEND")
    if not backend:
        backend = "postgresql" if production else "sqlite"
    if production and args.database and backend == "postgresql":
        raise EffectivenessStorageStateError(
            "production effectiveness database must be supplied through secret environment"
        )
    location = args.database
    if not location:
        location = (
            source.get("AEGIS_EFFECTIVENESS_DB_URL")
            or source.get("AEGIS_DB_URL")
            if backend == "postgresql"
            else source.get("AEGIS_EFFECTIVENESS_SQLITE_PATH", ":memory:")
        )
    if not location:
        raise SystemExit("effectiveness database location is required")
    return open_effectiveness_repository(backend=backend, location=location)


def run_effectiveness(args) -> int:
    try:
        repository = _repository(args)
        try:
            if args.effectiveness_command == "ingest-run":
                document = json.loads(Path(args.input).read_text(encoding="utf-8"))
                subject, inserted = ingest_lineage_document(repository, document)
                print(json.dumps({
                    "status": "RECORDED" if inserted else "IDEMPOTENT_REPLAY",
                    "subject_id": subject.subject_id,
                    "authoritative": repository.authoritative,
                }, indent=2))
                return 0
            if args.effectiveness_command in {"record-outcome", "amend-outcome"}:
                document = json.loads(Path(args.input).read_text(encoding="utf-8"))
                outcome = _outcome(document)
                if (args.effectiveness_command == "amend-outcome"
                        and outcome.supersedes_outcome_event_id is None):
                    raise ValueError("amend-outcome requires supersedes_outcome_event_id")
                subject = repository.subject(outcome.subject_id)
                if subject is None:
                    raise ValueError("outcome cannot be recorded without canonical lineage")
                print(json.dumps({
                    "lineage": {
                        "run_id": subject.run_id, "mission_id": subject.mission_id,
                        "opportunity_id": subject.opportunity_id, "technique": subject.technique,
                        "program_id": subject.program_id, "asset_id": subject.asset_id,
                    },
                    "state": outcome.state.value, "bounty_usd": (
                        None if outcome.bounty_usd is None else str(outcome.bounty_usd)
                    ),
                }, indent=2))
                if not args.confirm:
                    print("outcome not confirmed; no effectiveness record was created")
                    return 2
                record, inserted = record_human_outcome(repository, outcome)
                print(json.dumps({
                    "status": "RECORDED" if inserted else "IDEMPOTENT_REPLAY",
                    "outcome_event_id": record.outcome_event_id, "version": record.version,
                    "authoritative": repository.authoritative,
                }, indent=2))
                return 0
            if args.effectiveness_command == "record-cost":
                document = json.loads(Path(args.input).read_text(encoding="utf-8"))
                cost = CostObservation(
                    cost_observation_id=document["cost_observation_id"],
                    subject_id=document["subject_id"], campaign_id=document.get("campaign_id"),
                    model_api_cost_usd=_decimal(document, "model_api_cost_usd"),
                    scanner_compute_cost_usd=_decimal(document, "scanner_compute_cost_usd"),
                    cloud_cost_usd=_decimal(document, "cloud_cost_usd"),
                    oast_cost_usd=_decimal(document, "oast_cost_usd"),
                    browser_device_cost_usd=_decimal(document, "browser_device_cost_usd"),
                    human_review_minutes=_decimal(document, "human_review_minutes"),
                    human_submission_minutes=_decimal(document, "human_submission_minutes"),
                    human_other_minutes=_decimal(document, "human_other_minutes"),
                    human_hourly_rate_usd=_decimal(document, "human_hourly_rate_usd"),
                    observed_at=document["observed_at"], operator_id=document["operator_id"],
                    source_digest=document["source_digest"], idempotency_key=document["idempotency_key"],
                    calculation_version=document.get("calculation_version", "human-cost-v1"),
                )
                record, inserted = record_cost_observation(repository, cost)
                print(json.dumps({"status": "RECORDED" if inserted else "IDEMPOTENT_REPLAY",
                                  "cost_record_id": record.cost_record_id,
                                  "human_cost_usd": (None if cost.human_cost_usd is None else str(cost.human_cost_usd))}, indent=2))
                return 0
            if args.effectiveness_command == "campaign-create":
                document = json.loads(Path(args.input).read_text(encoding="utf-8"))
                campaign = CampaignInput(
                    campaign_id=document["campaign_id"], program_id=document["program_id"],
                    policy_snapshot_digest=document["policy_snapshot_digest"], scope_digest=document["scope_digest"],
                    selected_assets=tuple(document["selected_assets"]),
                    allowed_techniques=tuple(document["allowed_techniques"]),
                    time_budget_minutes=Decimal(str(document["time_budget_minutes"])),
                    cost_budget_usd=_decimal(document, "cost_budget_usd"), starts_at=document["starts_at"],
                    ends_at=document["ends_at"], operator_id=document["operator_id"],
                    idempotency_key=document["idempotency_key"],
                )
                record, inserted = repository.record_campaign(campaign)
                print(json.dumps({"status": "RECORDED" if inserted else "IDEMPOTENT_REPLAY",
                                  "campaign_id": record.payload.campaign_id}, indent=2))
                return 0
            if args.effectiveness_command == "campaign-event":
                document = json.loads(Path(args.input).read_text(encoding="utf-8"))
                event = CampaignEvent(
                    campaign_event_id=document["campaign_event_id"], campaign_id=document["campaign_id"],
                    event_type=document["event_type"], observed_at=document["observed_at"],
                    subject_id=document.get("subject_id"), metadata=document.get("metadata"),
                    source_digest=document["source_digest"], idempotency_key=document["idempotency_key"],
                )
                inserted = repository.record_campaign_event(event)
                print(json.dumps({"status": "RECORDED" if inserted else "IDEMPOTENT_REPLAY",
                                  "campaign_id": event.campaign_id}, indent=2))
                return 0
            if args.effectiveness_command == "shadow-rank":
                document = json.loads(Path(args.input).read_text(encoding="utf-8"))
                candidates = tuple(ShadowCandidate(
                    opportunity_id=item["opportunity_id"], technique=item["technique"],
                    existing_score=Decimal(str(item["existing_score"])),
                ) for item in document["opportunities"])
                batch = build_shadow_batch(
                    repository, candidates, batch_id=document["batch_id"],
                    idempotency_key=document["idempotency_key"],
                )
                inserted = repository.record_shadow_batch(batch)
                print(json.dumps({
                    "status": "RECORDED" if inserted else "IDEMPOTENT_REPLAY",
                    "batch_id": batch.batch_id,
                    "existing_order": [item.opportunity_id for item in sorted(
                        batch.entries, key=lambda item: item.existing_rank)],
                    "learned_order": [item.opportunity_id for item in sorted(
                        batch.entries, key=lambda item: item.learned_rank)],
                    "production_authority_changed": False,
                }, indent=2))
                return 0
            if args.effectiveness_command == "pending":
                print(render_v2_json({"queue": pending_review_queue(repository),
                                      "human_submission_mandatory": True}))
                return 0
            if args.effectiveness_command == "daily":
                document = daily_profitability_document(repository, computed_at=utc_now())
                output = render_v2_json(document) if args.format == "json" else render_v2_markdown(document)
                if args.output:
                    Path(args.output).write_text(output + "\n", encoding="utf-8")
                else:
                    print(output)
                return 0
            metrics = calculate_metrics(repository)
            output = (
                render_json(metrics, authoritative=repository.authoritative)
                if args.format == "json"
                else render_markdown(metrics, authoritative=repository.authoritative)
            )
            if args.output:
                Path(args.output).write_text(output + "\n", encoding="utf-8")
            else:
                print(output)
            return 0
        finally:
            repository.close()
    except (EffectivenessError, KeyError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "UNAVAILABLE_OR_INVALID", "reason": str(exc)}), file=sys.stderr)
        return 1
