"""Rank targets by how PICKED-OVER they are, not by bounty ceiling.

The evidence from a full session of hunting was unambiguous: zero findings across the
famous, heavily-audited targets (Circle, Kubernetes, Chia, Vercel), and the one real
find was owncloud — mid-size and comparatively un-mined. Chasing the biggest bounty
ceiling is the wrong policy; chasing the softest reachable target is the right one.

Saturation can't be read from HackerOne's hacker API (it exposes only program age),
but GitHub exposes the two signals that matter most:

* **published security advisories** — a direct count of how many vulnerabilities have
  already been found and fixed. The single strongest "how mined is this" proxy.
* **stars** — attention, and thus how many researchers have already looked.

``findability`` combines these into 0..1 (higher = softer = hunt sooner). It is a
pure function so ranking is deterministic and testable; ``gather_signals`` fills the
inputs from GitHub best-effort.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class TargetSignals:
    repository: str
    stars: int = 0
    advisories: int = 0          # published GitHub security advisories (GHSA)
    pushed_days_ago: int = 3650  # recency of the last push
    program_age_days: int = 3650 # how long the bounty program has been open


def _attention_penalty(stars: int) -> float:
    """0 (nobody watching) .. 1 (everybody watching). log-scaled: 10 stars ≈ 0.25,
    1k ≈ 0.6, 100k ≈ 1.0."""
    if stars <= 1:
        return 0.0
    return min(1.0, math.log10(stars) / 5.0)


def _audit_penalty(advisories: int) -> float:
    """0 (no advisory has ever been published) .. 1 (many). The strongest signal that
    a codebase has already been worked over. 1 advisory ≈ 0.3, 5 ≈ 0.6, 25+ ≈ 1.0."""
    if advisories <= 0:
        return 0.0
    return min(1.0, math.log10(advisories + 1) / math.log10(26))


def findability(sig: TargetSignals) -> float:
    """0..1 softness score — higher means less picked-over, hunt sooner.

    Audit history dominates (0.6): an advisory-heavy repo has demonstrably been mined.
    Attention is secondary (0.3). A small recency bonus (0.1) favours actively-changed
    code, where regressions and fresh bugs live (and where programs pay a bonus)."""
    audit = 1.0 - _audit_penalty(sig.advisories)
    attention = 1.0 - _attention_penalty(sig.stars)
    recency = 1.0 if sig.pushed_days_ago <= 30 else (0.5 if sig.pushed_days_ago <= 365 else 0.2)
    return round(0.6 * audit + 0.3 * attention + 0.1 * recency, 4)


def rank_targets(signals: list[TargetSignals]) -> list[tuple[str, float]]:
    """Repositories sorted softest-first, with their findability scores."""
    scored = [(s.repository, findability(s)) for s in signals]
    scored.sort(key=lambda rs: (-rs[1], rs[0]))
    return scored


def gather_signals(repository: str, *, gh_client, program_age_days: int = 3650) -> TargetSignals:
    """Best-effort GitHub signal collection. ``gh_client`` is an httpx.Client with the
    GitHub Accept/Authorization headers already set. Missing data degrades to the
    conservative (harder-looking) default rather than raising."""
    from datetime import datetime, timezone

    def _get_json(url, **params):
        try:
            r = gh_client.get(url, params=params or None, timeout=20)
            return r.json() if r.status_code == 200 else None
        except Exception:
            return None

    meta = _get_json(f"https://api.github.com/repos/{repository}") or {}
    stars = int(meta.get("stargazers_count") or 0)

    pushed = meta.get("pushed_at")
    pushed_days = 3650
    if pushed:
        try:
            dt = datetime.fromisoformat(pushed.replace("Z", "+00:00"))
            pushed_days = max(0, (datetime.now(timezone.utc) - dt).days)
        except ValueError:
            pass

    # count published advisories (one page of 100 is plenty to distinguish 0 / few / many)
    adv = _get_json(f"https://api.github.com/repos/{repository}/security-advisories",
                    per_page=100, state="published")
    advisories = len(adv) if isinstance(adv, list) else 0

    return TargetSignals(
        repository=repository, stars=stars, advisories=advisories,
        pushed_days_ago=pushed_days, program_age_days=program_age_days,
    )
