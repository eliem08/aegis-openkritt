"""Unified review console — one ranked view over candidates from every source.

The UI needs a single, source-labeled, priority-ranked picture of what a scan
turned up, whoever produced it: native Aegis analyzers, the lab contract-property
pass, and imported open·kritt findings all arrive as
:class:`~aegis.model.Candidate` objects. :func:`build_console` merges and
de-duplicates them (by :meth:`Candidate.fingerprint`), ranks by the §8 priority
score, and returns a JSON-serializable model the ``/ui`` page renders.

It is a *review* surface, not a verdict: every item carries its verification
status (a candidate is a hypothesis until Aegis's own gate confirms it), and no
raw secret or exploit payload reaches it — the candidates were already redacted at
the point they were created.
"""

from __future__ import annotations

from datetime import datetime, timezone

from aegis.model import Candidate
from aegis.model.finding import priority_score

_SOURCE_LABELS = {
    "integration:openkritt": "open-kritt",
    "analyzer:contract": "contract",
}


def _source_of(candidate: Candidate) -> str:
    worker = candidate.worker or ""
    if worker in _SOURCE_LABELS:
        return _SOURCE_LABELS[worker]
    if worker.startswith("integration:"):
        return worker.split(":", 1)[1]
    if worker.startswith("analyzer:"):
        return "aegis"
    return worker or "aegis"


def _severity(candidate: Candidate) -> str:
    if candidate.impact:                       # open·kritt carries an explicit level
        return candidate.impact.strip().lower()
    bi = candidate.business_impact
    if bi >= 0.85:
        return "critical"
    if bi >= 0.6:
        return "high"
    if bi >= 0.4:
        return "medium"
    return "low"


_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def build_console(candidates, *, scan_id: str = "", now=None, calibration=None) -> dict:
    """Merge candidates into one ranked, de-duplicated review model (JSON-able).

    When a ``calibration`` (``aegis.learn.Calibration``) is supplied, each item's
    ranking priority is scaled by the learned per-detector/CWE precision, so the
    console reorders itself as verdicts accumulate — the learning loop, made visible.
    """
    now = now or datetime.now(timezone.utc)

    # De-duplicate by family fingerprint, keeping the highest-priority member and
    # counting how many collapsed into it.
    reps: dict[str, dict] = {}
    for c in candidates:
        key = c.fingerprint()
        pr = round(priority_score(c) * _cal_factor(calibration, c), 4)
        item = reps.get(key)
        if item is None or pr > item["priority"]:
            new = _item(c, pr, keep_count=(item["duplicate_count"] if item else 0))
            if calibration is not None:
                new["learned_prior"] = round(calibration.prior(detector=c.worker, cwe=c.cwe), 3)
            reps[key] = new
        else:
            item["duplicate_count"] += 1

    items = sorted(
        reps.values(),
        key=lambda it: (it["priority"], _SEVERITY_ORDER.get(it["severity"], 0)),
        reverse=True,
    )
    for rank, it in enumerate(items, start=1):
        it["rank"] = rank

    by_source: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    verified = 0
    for it in items:
        by_source[it["source"]] = by_source.get(it["source"], 0) + 1
        by_severity[it["severity"]] = by_severity.get(it["severity"], 0) + 1
        if it["status"] == "verified":
            verified += 1

    return {
        "scan_id": scan_id,
        "generated_at": now.isoformat(),
        "totals": {
            "candidates": len(items),
            "verified": verified,
            "hypotheses": len(items) - verified,
            "by_source": by_source,
            "by_severity": by_severity,
        },
        "sources": sorted(by_source),
        "items": items,
    }


def _cal_factor(calibration, candidate) -> float:
    return calibration.factor(candidate) if calibration is not None else 1.0


def _item(c: Candidate, priority: float, *, keep_count: int) -> dict:
    return {
        "rank": 0,
        "priority": priority,
        "source": _source_of(c),
        "worker": c.worker,
        "title": c.title(),
        "weakness": c.weakness_label(),
        "cwe": c.cwe,
        "asset": c.asset,
        "route": c.route,
        "code_location": c.code_location,
        "severity": _severity(c),
        "confidence": round(c.confidence, 3),
        "business_impact": round(c.business_impact, 3),
        "action": c.action,
        "observed": c.observed,
        "expected": c.expected,
        "status": "verified" if c.evidence_id else "hypothesis",
        "duplicate_count": keep_count + 1,
    }
