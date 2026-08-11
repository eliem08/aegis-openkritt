"""Dependency-light canonical effectiveness funnel validation."""

from __future__ import annotations

from .models import EffectivenessFact, FactType
from .repository import EffectivenessRepository


class LineageValidationError(ValueError):
    pass


_CANDIDATE_STAGES = {
    FactType.CANDIDATE_GENERATED, FactType.RUNTIME_OBSERVED,
    FactType.LOCALLY_REPRODUCED, FactType.INDEPENDENTLY_VERIFIED,
    FactType.HUMAN_APPROVED, FactType.SUBMITTED, FactType.TRIAGED,
    FactType.ACCEPTED, FactType.PAID,
}
_DECISION_STAGES = {
    FactType.HUMAN_APPROVED, FactType.SUBMITTED, FactType.TRIAGED,
    FactType.ACCEPTED, FactType.PAID,
}
_SUBMISSION_STAGES = {
    FactType.SUBMITTED, FactType.TRIAGED, FactType.ACCEPTED, FactType.PAID,
}


def record_funnel_fact(
    repository: EffectivenessRepository,
    fact: EffectivenessFact,
) -> bool:
    """Append a V2 funnel transition after validating evolving lineage."""
    subject = repository.subject(fact.subject_id)
    if subject is None:
        raise LineageValidationError("funnel fact requires canonical subject lineage")
    if fact.model_version != "funnel-v2":
        raise LineageValidationError("new funnel facts require model_version funnel-v2")
    metadata = dict(fact.metadata or {})
    required = []
    if fact.fact_type in _CANDIDATE_STAGES:
        required.append("candidate_finding_id")
    if fact.fact_type in _DECISION_STAGES:
        required.append("human_decision_id")
    if fact.fact_type in _SUBMISSION_STAGES:
        required.append("submission_id")
    for name in required:
        value = str(metadata.get(name) or getattr(subject, name) or "").strip()
        if not value:
            raise LineageValidationError(
                f"funnel stage {fact.fact_type.value} requires {name}"
            )
        metadata[name] = value
    prior = tuple(item for item in repository.facts() if item.subject_id == fact.subject_id)
    for name in ("candidate_finding_id", "human_decision_id", "submission_id"):
        current = metadata.get(name)
        known = {
            str(item.metadata[name]) for item in prior
            if item.metadata and item.metadata.get(name) is not None
        }
        subject_value = getattr(subject, name)
        if subject_value:
            known.add(subject_value)
        if current is not None and known and str(current) not in known:
            raise LineageValidationError(f"funnel lineage {name} conflicts with prior facts")
    canonical = EffectivenessFact(
        fact_id=fact.fact_id, subject_id=fact.subject_id, fact_type=fact.fact_type,
        observed_at=fact.observed_at, source_digest=fact.source_digest,
        idempotency_key=fact.idempotency_key, metadata=metadata,
        model_version=fact.model_version,
    )
    return repository.record_fact(canonical)
