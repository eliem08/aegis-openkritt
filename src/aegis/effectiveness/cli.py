"""Operator CLI handlers for effectiveness measurement."""

from __future__ import annotations

import json
import os
import sys
from decimal import Decimal
from pathlib import Path

from .metrics import calculate_metrics
from .models import OutcomeInput, OutcomeState
from .report import render_json, render_markdown
from .repository import (
    EffectivenessError,
    EffectivenessStorageStateError,
    open_effectiveness_repository,
)
from .service import ingest_lineage_document, record_human_outcome
from .shadow import ShadowCandidate, build_shadow_batch


def add_effectiveness_parser(commands) -> None:
    effectiveness = commands.add_parser("effectiveness")
    effectiveness_commands = effectiveness.add_subparsers(
        dest="effectiveness_command", required=True,
    )
    for name in ("ingest-run", "record-outcome", "shadow-rank", "report"):
        command = effectiveness_commands.add_parser(name)
        command.add_argument("--backend", choices=("postgresql", "sqlite"))
        command.add_argument("--database")
        if name in {"ingest-run", "record-outcome", "shadow-rank"}:
            command.add_argument("--input", required=True)
        if name == "record-outcome":
            command.add_argument("--confirm", action="store_true")
        if name == "report":
            command.add_argument("--format", choices=("json", "markdown"), default="json")
            command.add_argument("--output")


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
            if args.effectiveness_command == "record-outcome":
                document = json.loads(Path(args.input).read_text(encoding="utf-8"))
                outcome = OutcomeInput(
                    subject_id=document["subject_id"], state=OutcomeState(document["state"]),
                    submitted_severity=document.get("submitted_severity"),
                    triaged_severity=document.get("triaged_severity"),
                    bounty_usd=(None if document.get("bounty_usd") is None
                                else Decimal(str(document["bounty_usd"]))),
                    submitted_at=document.get("submitted_at"),
                    triaged_at=document.get("triaged_at"), resolved_at=document.get("resolved_at"),
                    human_review_minutes=(None if document.get("human_review_minutes") is None
                                          else Decimal(str(document["human_review_minutes"]))),
                    model_api_cost_usd=(None if document.get("model_api_cost_usd") is None
                                        else Decimal(str(document["model_api_cost_usd"]))),
                    compute_cost_usd=(None if document.get("compute_cost_usd") is None
                                      else Decimal(str(document["compute_cost_usd"]))),
                    analyst_note=document.get("analyst_note"), operator_id=document["operator_id"],
                    source_digest=document["source_digest"],
                    idempotency_key=document["idempotency_key"],
                    supersedes_outcome_event_id=document.get("supersedes_outcome_event_id"),
                )
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
