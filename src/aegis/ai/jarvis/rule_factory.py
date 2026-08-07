"""Detection-rule synthesis contracts and deterministic validation gates."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from .state_store import RuleCandidateRecord, VulnerabilityFamily


@dataclass(frozen=True)
class RuleDraft:
    rule_id: str
    engine: str
    family_id: str
    rule_text: str
    rationale: str


@dataclass(frozen=True)
class RuleValidationResult:
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    precision: float
    recall: float
    promotable: bool


def _stable_rule_id(engine: str, family: VulnerabilityFamily) -> str:
    material = "\x1f".join(
        (
            engine,
            family.family_id,
            family.mechanism.strip().lower(),
            family.invariant.strip().lower(),
            family.cwe.strip().upper(),
        )
    )
    return f"aegis-{engine}-{sha256(material.encode()).hexdigest()[:16]}"


def draft_detection_rule(family: VulnerabilityFamily, *, engine: str) -> RuleDraft:
    """Create a reviewable detector skeleton from a confirmed vulnerability family.

    This function deliberately produces a declarative skeleton rather than executing
    or publishing scanner code. A separate validator must prove the draft against
    positive and negative fixtures before promotion.
    """
    normalized_engine = engine.strip().lower()
    if normalized_engine not in {"semgrep", "codeql"}:
        raise ValueError("engine must be semgrep or codeql")
    if family.confidence < 0.7:
        raise ValueError("family confidence is too low for rule synthesis")
    rule_id = _stable_rule_id(normalized_engine, family)
    if normalized_engine == "semgrep":
        text = (
            f"rules:\n  - id: {rule_id}\n"
            "    message: Aegis family detector candidate\n"
            "    severity: WARNING\n"
            "    metadata:\n"
            f"      family_id: {family.family_id}\n"
            f"      cwe: {family.cwe or 'UNSPECIFIED'}\n"
            "      validation: fixture-gated\n"
            "    patterns:\n"
            "      - pattern: $EXPR\n"
        )
    else:
        text = (
            f"/** Aegis family detector candidate: {family.family_id} */\n"
            "import semmle.code.$LANG.dataflow.DataFlow\n\n"
            "from DataFlow::Node source, DataFlow::Node sink\n"
            "where source = source and sink = sink\n"
            "select sink, \"Aegis family detector candidate\"\n"
        )
    return RuleDraft(
        rule_id=rule_id,
        engine=normalized_engine,
        family_id=family.family_id,
        rule_text=text,
        rationale=(
            f"Abstract {family.mechanism} while preserving invariant: {family.invariant}"
        ),
    )


def validate_rule_fixture_counts(
    *,
    true_positives: int,
    false_positives: int,
    false_negatives: int,
    true_negatives: int,
    minimum_precision: float = 0.9,
    minimum_recall: float = 0.6,
    minimum_positive_fixtures: int = 2,
    minimum_negative_fixtures: int = 2,
) -> RuleValidationResult:
    counts = (true_positives, false_positives, false_negatives, true_negatives)
    if any(value < 0 for value in counts):
        raise ValueError("fixture counts must be non-negative")
    positive_fixtures = true_positives + false_negatives
    negative_fixtures = true_negatives + false_positives
    precision_denominator = true_positives + false_positives
    recall_denominator = true_positives + false_negatives
    precision = true_positives / precision_denominator if precision_denominator else 0.0
    recall = true_positives / recall_denominator if recall_denominator else 0.0
    promotable = (
        positive_fixtures >= minimum_positive_fixtures
        and negative_fixtures >= minimum_negative_fixtures
        and precision >= minimum_precision
        and recall >= minimum_recall
    )
    return RuleValidationResult(
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        true_negatives=true_negatives,
        precision=precision,
        recall=recall,
        promotable=promotable,
    )


def to_record(draft: RuleDraft, result: RuleValidationResult) -> RuleCandidateRecord:
    return RuleCandidateRecord(
        rule_id=draft.rule_id,
        engine=draft.engine,
        family_id=draft.family_id,
        rule_text=draft.rule_text,
        positive_fixtures=result.true_positives + result.false_negatives,
        negative_fixtures=result.true_negatives + result.false_positives,
        precision=result.precision,
        recall=result.recall,
        status="validated" if result.promotable else "needs_review",
    )
