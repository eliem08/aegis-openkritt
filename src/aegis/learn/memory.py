"""Retrieval memory — how the LLM planner learns from past verdicts.

The calibration priors reweight ranking; this half feeds the *language model*. It
recalls the most relevant judged findings (confirmed and false-positive) and hands
them to the planner as few-shot context, so DeepSeek conditions its next plan on
what actually panned out before. No fine-tuning: the model learns in-context, and
the memory grows automatically as verdicts land.

Only short, redacted summaries are stored/recalled — never raw payloads or secrets.
"""

from __future__ import annotations

from .calibration import Calibration
from .store import Verdict


def _relevance(o, cwe: str, detector: str) -> int:
    score = 0
    if cwe and o.cwe == cwe:
        score += 2
    if detector and o.detector == detector:
        score += 1
    return score


def recall(outcomes, *, cwe: str = "", detector: str = "", k: int = 3) -> list[dict]:
    """Most recent judged examples relevant to a CWE/detector (most recent first)."""
    judged = [o for o in outcomes if Verdict(o.verdict) is not Verdict.PENDING]
    scored = sorted(judged, key=lambda o: (_relevance(o, cwe, detector), o.created_at), reverse=True)
    out = []
    for o in scored:
        if _relevance(o, cwe, detector) == 0 and (cwe or detector):
            continue
        out.append({"cwe": o.cwe, "detector": o.detector,
                    "verdict": Verdict(o.verdict).value, "summary": o.summary})
        if len(out) >= k:
            break
    return out


def learned_context(outcomes, *, cwe: str = "", detector: str = "", k: int = 3) -> dict:
    """Planner-injectable knowledge: priors summary + confirmed/false-positive examples."""
    cal = Calibration.from_outcomes(outcomes)
    confirmed = [o for o in recall(outcomes, cwe=cwe, detector=detector, k=k * 2)
                 if o["verdict"] in (Verdict.CONFIRMED.value, Verdict.DUPLICATE.value)][:k]
    false_pos = [o for o in recall(outcomes, cwe=cwe, detector=detector, k=k * 2)
                 if o["verdict"] == Verdict.FALSE_POSITIVE.value][:k]
    return {
        "prior_precision": round(cal.prior(detector=detector, cwe=cwe), 3),
        "confirmed_examples": [e["summary"] for e in confirmed if e["summary"]],
        "false_positive_examples": [e["summary"] for e in false_pos if e["summary"]],
        "note": "Prefer patterns like the confirmed examples; be skeptical of the "
                "false-positive ones. These are learned from prior verdicts.",
    }


class PlannerKnowledge:
    """Adapter that lets ``LLMPlanner`` pull learned context into its prompt.

    Implements the planner's ``knowledge`` hook: ``context(inputs, surface) -> dict``.
    As the outcome store grows, the same planner produces better-conditioned plans —
    the concrete sense in which "the LLM auto-learns."
    """

    def __init__(self, store, *, k: int = 3):
        self._store = store
        self._k = k

    def context(self, inputs, surface) -> dict:
        outcomes = self._store.all()
        if not outcomes:
            return {}
        return learned_context(outcomes, k=self._k)
