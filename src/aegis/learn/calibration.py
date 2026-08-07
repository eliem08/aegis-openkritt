"""Calibration — turn accumulated verdicts into priors that reweight findings.

This is the deterministic half of the learning loop. From the outcome store it
computes, per **detector** and per **CWE**, the precision seen so far (how often
that source/weakness turned out to be a true detection vs. a false positive), with
Laplace smoothing so a single verdict doesn't swing everything. Those priors then
scale a candidate's ranking: a source that keeps producing false positives sinks,
a reliable one rises — automatically, as feedback arrives.

It is a *prior*, never a gate: calibration reorders and annotates candidates, it
never drops one. Verification still decides what is real.
"""

from __future__ import annotations

from dataclasses import dataclass

from .store import Verdict


@dataclass(frozen=True)
class _Tally:
    true: int = 0
    false: int = 0

    def precision(self, alpha: float, beta: float) -> float:
        return (self.true + alpha) / (self.true + self.false + alpha + beta)

    @property
    def n(self) -> int:
        return self.true + self.false


class Calibration:
    def __init__(self, by_detector, by_cwe, *, alpha: float = 1.0, beta: float = 1.0,
                 base: float = 0.5):
        self._by_detector = by_detector
        self._by_cwe = by_cwe
        self._alpha = alpha
        self._beta = beta
        self._base = base

    @classmethod
    def from_outcomes(cls, outcomes, **kw) -> Calibration:
        by_detector: dict[str, _Tally] = {}
        by_cwe: dict[str, _Tally] = {}
        for o in outcomes:
            v = Verdict(o.verdict)
            if v is Verdict.PENDING:
                continue
            _bump(by_detector, o.detector, v)
            _bump(by_cwe, o.cwe, v)
        return cls(by_detector, by_cwe, **kw)

    def prior(self, *, detector: str = "", cwe: str = "") -> float:
        """Smoothed precision for this detector/CWE, blending whatever evidence exists."""
        priors = []
        d = self._by_detector.get(detector)
        if d is not None:
            priors.append(d.precision(self._alpha, self._beta))
        c = self._by_cwe.get(cwe)
        if c is not None:
            priors.append(c.precision(self._alpha, self._beta))
        return sum(priors) / len(priors) if priors else self._base

    def factor(self, candidate) -> float:
        """Ranking multiplier in [0.2, 1.8]: 0.5 precision -> 1.0 (neutral)."""
        p = self.prior(detector=getattr(candidate, "worker", ""), cwe=getattr(candidate, "cwe", ""))
        return max(0.2, min(1.8, 2.0 * p))

    def has_evidence(self, candidate) -> bool:
        return (getattr(candidate, "worker", "") in self._by_detector
                or getattr(candidate, "cwe", "") in self._by_cwe)


def _bump(table: dict, key: str, verdict: Verdict) -> None:
    if not key:
        return
    t = table.get(key, _Tally())
    if verdict.is_true_detection:
        table[key] = _Tally(t.true + 1, t.false)
    elif verdict.is_false:
        table[key] = _Tally(t.true, t.false + 1)
