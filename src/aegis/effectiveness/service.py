"""Canonical lineage ingestion and human-reviewed outcome service."""

from __future__ import annotations

from hashlib import sha256
from typing import Any, Mapping

from aegis.production.operator_manifest import document_digest

from .funnel import LineageValidationError, record_funnel_fact
from .models import (
    CostObservation,
    CostRecord,
    EffectivenessFact,
    EffectivenessSubject,
    FactType,
    OutcomeInput,
    OutcomeRecord,
    OutcomeState,
    payload_digest,
)
from .repository import EffectivenessRepository

__all__ = ["LineageValidationError", "record_funnel_fact"]


def _required(document: Mapping[str, Any], name: str) -> str:
    value = str(document.get(name) or "").strip()
    if not value:
        raise LineageValidationError(f"lineage field {name} is required")
    return value


def ingest_lineage_document(
    repository: EffectivenessRepository,
    document: Mapping[str, Any],
) -> tuple[EffectivenessSubject, bool]:
    """Validate a canonical exported run/mission/opportunity lineage and persist facts."""
    manifest = dict(document.get("manifest") or {})
    manifest_digest = str(manifest.pop("manifest_digest", ""))
    if not manifest_digest or manifest_digest != document_digest(manifest):
        raise LineageValidationError("canonical run manifest digest mismatch")
    lineage = dict(document.get("lineage") or {})
    run_id = _required(manifest, "run_id")
    if _required(lineage, "run_id") != run_id:
        raise LineageValidationError("lineage run_id does not match canonical manifest")
    program_id = _required(lineage, "program_id")
    if program_id != _required(manifest, "program_handle"):
        raise LineageValidationError("lineage program does not match canonical manifest")
    asset_id = _required(lineage, "asset_id")
    selected_assets = tuple(str(item) for item in manifest.get("selected_assets") or ())
    if asset_id not in selected_assets:
        raise LineageValidationError("lineage asset is not selected in canonical manifest")
    evidence_digest = _required(lineage, "evidence_digest").lower()
    source_digest = payload_digest(document)
    stable = {
        "run_id": run_id,
        "mission_id": _required(lineage, "mission_id"),
        "opportunity_id": _required(lineage, "opportunity_id"),
        "technique": _required(lineage, "technique"),
    }
    subject_id = str(lineage.get("subject_id") or (
        "subject-" + sha256(payload_digest(stable).encode()).hexdigest()[:24]
    ))
    created_at = str(lineage.get("created_at") or manifest.get("created_at") or "")
    subject = EffectivenessSubject(
        subject_id=subject_id, run_id=run_id, mission_id=stable["mission_id"],
        opportunity_id=stable["opportunity_id"], technique=stable["technique"],
        program_id=program_id, asset_id=asset_id,
        weakness_family=_required(lineage, "weakness_family"),
        asset_class=_required(lineage, "asset_class"),
        authentication_mode=_required(lineage, "authentication_mode"),
        execution_mode=_required(lineage, "execution_mode"),
        evidence_digest=evidence_digest, source_digest=source_digest, created_at=created_at,
        candidate_finding_id=(str(lineage["candidate_finding_id"]).strip()
                              if lineage.get("candidate_finding_id") else None),
        human_decision_id=(str(lineage["human_decision_id"]).strip()
                           if lineage.get("human_decision_id") else None),
        submission_id=(str(lineage["submission_id"]).strip()
                       if lineage.get("submission_id") else None),
    )
    fact_names = list(document.get("facts") or [FactType.OPPORTUNITY_GENERATED.value])
    if FactType.OPPORTUNITY_GENERATED.value not in fact_names:
        fact_names.insert(0, FactType.OPPORTUNITY_GENERATED.value)
    observed_at = str(lineage.get("observed_at") or created_at)
    facts = tuple(EffectivenessFact(
        fact_id=f"fact-{sha256(f'{subject_id}:{name}:{source_digest}'.encode()).hexdigest()[:24]}",
        subject_id=subject_id, fact_type=FactType(name), observed_at=observed_at,
        source_digest=source_digest, idempotency_key=f"{subject_id}:{name}:{source_digest}",
    ) for name in dict.fromkeys(fact_names))
    inserted = repository.record_subject(subject, facts)
    return subject, inserted


def record_human_outcome(
    repository: EffectivenessRepository,
    outcome: OutcomeInput,
) -> tuple[OutcomeRecord, bool]:
    subject = repository.subject(outcome.subject_id)
    if subject is None:
        raise LineageValidationError("outcome cannot be recorded without canonical lineage")
    v2_facts = tuple(
        fact for fact in repository.facts()
        if fact.subject_id == outcome.subject_id and fact.model_version == "funnel-v2"
    )
    external_states = {
        OutcomeState.ACCEPTED, OutcomeState.DUPLICATE, OutcomeState.INFORMATIVE,
        OutcomeState.NOT_APPLICABLE, OutcomeState.WITHDRAWN, OutcomeState.PENDING,
    }
    if v2_facts and outcome.state in external_states:
        if not any(fact.fact_type is FactType.SUBMITTED for fact in v2_facts):
            raise LineageValidationError(
                "external V2 outcome requires traceable submission lineage"
            )
    return repository.record_outcome(outcome)


def record_cost_observation(
    repository: EffectivenessRepository,
    cost: CostObservation,
) -> tuple[CostRecord, bool]:
    if repository.subject(cost.subject_id) is None:
        raise LineageValidationError("cost cannot be recorded without canonical lineage")
    return repository.record_cost(cost)
