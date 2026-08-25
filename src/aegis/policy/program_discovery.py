"""Fresh-target discovery — rank paying, source-available, LESS-HUNTED programs.

The elite, well-hunted programs (GitLab, auth0, Matomo, Nextcloud, Zuul) have a
high clean-rate for source review; the wins this project has landed came from
*newer / less-audited* code. This module turns a program corpus into a ranked
candidate queue that biases toward exactly that: programs that (a) expose
**source** (owner/repo) targets, (b) **pay cash**, and (c) look **less-hunted**
(low report count / low saturation), each already passed through
:func:`aegis.policy.program_eligibility.verify_target` so out-of-scope,
suspended, and excluded assets never reach the hunt loop.

Snapshot data (``reports/programs.json``) is stale by design (that is the whole
scope lesson), so every candidate is emitted with ``needs_live_verify=True`` — the
gate answers "is this eligible *in the snapshot*"; the operator/Jarvis must
re-confirm against the live policy immediately before hunting.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from aegis.policy.program_eligibility import (
    Eligibility,
    EligibilityResult,
    canonical_repo,
    verify_target,
)

__all__ = ["Candidate", "discover"]


@dataclass(frozen=True)
class Candidate:
    program: str
    platform: str
    target: str                 # canonical owner/repo
    verdict: Eligibility
    pays_cash: bool
    score: float                # higher = hunt sooner (fresher / less-hunted)
    reasons: tuple[str, ...] = field(default_factory=tuple)
    needs_live_verify: bool = True

    def __str__(self) -> str:  # pragma: no cover - convenience
        return (f"{self.score:6.1f}  {self.target:40s} @ {self.program:28s} "
                f"[{self.verdict.value}, cash={self.pays_cash}]")


def _repo_targets(program: dict) -> list[str]:
    """Distinct canonical owner/repo targets from the eligible + targets lists."""
    seen: dict[str, None] = {}
    for key in ("bounty_eligible_targets", "targets"):
        for entry in program.get(key) or []:
            repo = canonical_repo(str(entry))
            if repo and repo not in seen:
                seen[repo] = None
    return list(seen)


def _freshness_score(program: dict, elig: EligibilityResult) -> tuple[float, list[str]]:
    """Higher score = fresher / less-hunted / better-paying. Explainable components."""
    reasons: list[str] = []

    # (1) Less-hunted by saturation (0=untouched .. 1=saturated); unknown → neutral 0.5.
    sat = program.get("saturation")
    sat = float(sat) if isinstance(sat, (int, float)) else 0.5
    sat = min(max(sat, 0.0), 1.0)
    unhunted = (1.0 - sat) * 50.0
    reasons.append(f"saturation={sat:.2f} → +{unhunted:.0f}")

    # (2) Less-hunted by report volume — fewer prior reports = fresher wood.
    reports = program.get("paid_reports")
    reports = int(reports) if isinstance(reports, (int, float)) else 0
    fresh = (1.0 / (1.0 + reports)) * 30.0
    reasons.append(f"paid_reports={reports} → +{fresh:.0f}")

    # (3) Payout ceiling bonus (capped — payout matters, but odds matter more).
    ceiling = program.get("reward_ceiling") or 0
    try:
        ceiling = float(ceiling)
    except (TypeError, ValueError):
        ceiling = 0.0
    ceil_bonus = (min(ceiling, 25000.0) / 25000.0) * 20.0 if ceiling > 0 else 0.0
    reasons.append(f"ceiling=${int(ceiling)} → +{ceil_bonus:.0f}")

    # (4) Recency nudge — newer programs are less picked-over.
    age = program.get("age_months")
    if isinstance(age, (int, float)) and age >= 0:
        recency = max(0.0, 10.0 - math.log1p(age) * 3.0)
        reasons.append(f"age_months={int(age)} → +{recency:.0f}")
    else:
        recency = 0.0

    return unhunted + fresh + ceil_bonus + recency, reasons


def discover(
    programs: list[dict],
    *,
    include: tuple[Eligibility, ...] = (Eligibility.SUBMITTABLE,),
    require_cash: bool = True,
    limit: int | None = None,
) -> list[Candidate]:
    """Rank source-available program targets, gated by eligibility.

    Args:
        programs: program records (e.g. from ``reports/programs.json``).
        include: which eligibility verdicts to keep. Default: cash-submittable only.
                 Pass ``(SUBMITTABLE, CREDIT_ONLY)`` for credit/CVE runs too.
        require_cash: drop candidates the gate says don't pay cash.
        limit: cap the returned queue length.

    Returns:
        Candidates sorted by score descending (freshest / least-hunted first).
    """
    out: list[Candidate] = []
    for program in programs:
        handle = str(program.get("handle") or program.get("url") or "?")
        platform = str(program.get("platform") or "?")
        for repo in _repo_targets(program):
            elig = verify_target(program, repo)
            if elig.verdict not in include:
                continue
            if require_cash and not elig.pays_cash:
                continue
            score, why = _freshness_score(program, elig)
            out.append(Candidate(
                program=handle,
                platform=platform,
                target=repo,
                verdict=elig.verdict,
                pays_cash=elig.pays_cash,
                score=round(score, 2),
                reasons=tuple(list(elig.reasons) + why),
            ))
    out.sort(key=lambda c: c.score, reverse=True)
    return out[:limit] if limit else out
