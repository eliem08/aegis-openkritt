"""Reward-threshold awareness — so "profitable" means "findings that actually pay".

A program's scope severity ceiling (from the API) is not its reward *floor*. Coinbase,
for example, pays for cb-mpc only on *easily-exploitable* high/critical key-compromise;
Low/Medium (and "hard to exploit") are explicitly **out of scope → $0**. The structured
API does not expose that — it lives in the human-readable program policy — so it is an
operator-maintained overlay here, seeded with what we've read, and refinable as
HackerOne submission outcomes come back (N/A on a Medium teaches the floor).

Two uses:
* **Selection** — deprioritize (or skip) programs whose realistic yield can't clear
  their reward floor, so the hunter spends effort where findings pay.
* **Triage** — flag a finding whose severity is below the program's floor as "likely
  out of scope" *before* it's submitted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

SEVERITY_RANK = {
    "": 0, "none": 0, "info": 0, "informational": 0,
    "low": 1, "medium": 2, "high": 3, "critical": 4, "extreme": 5,
}


def sev_rank(sev: str) -> int:
    return SEVERITY_RANK.get(str(sev or "").strip().lower(), 0)


@dataclass(frozen=True)
class RewardPolicy:
    handle: str
    min_severity: str = "low"              # lowest severity the program actually rewards
    excludes_hard_to_exploit: bool = False  # won't pay hard-to-exploit even at high impact
    notes: str = ""


# Seeded from program pages we've read. The operator extends this via an overlay JSON.
DEFAULT_REWARD_POLICIES: dict[str, RewardPolicy] = {
    "coinbase": RewardPolicy(
        "coinbase", min_severity="high", excludes_hard_to_exploit=True,
        notes="cb-mpc: Low/Medium out of scope; hard-to-exploit is scored Medium => $0. "
              "Needs easily-exploitable key-compromise/RCE with no unlikely precondition."),
}


def load_reward_policies(path: str | None = None) -> dict[str, RewardPolicy]:
    """Defaults merged with an operator overlay JSON ({handle: {min_severity, ...}})."""
    policies = dict(DEFAULT_REWARD_POLICIES)
    if path:
        try:
            with open(path, encoding="utf-8") as fh:
                for handle, spec in (json.load(fh) or {}).items():
                    policies[handle] = RewardPolicy(
                        handle=handle,
                        min_severity=str(spec.get("min_severity", "low")),
                        excludes_hard_to_exploit=bool(spec.get("excludes_hard_to_exploit", False)),
                        notes=str(spec.get("notes", "")))
        except (OSError, ValueError):
            pass
    return policies


def meets_floor(severity: str, policy: RewardPolicy | None) -> bool:
    """Would a finding of this severity clear the program's reward floor?"""
    if policy is None:
        return True
    return sev_rank(severity) >= sev_rank(policy.min_severity)


def reward_factor(policy: RewardPolicy | None) -> float:
    """Ranking multiplier: programs that pay for lower severities are worth more of
    our (often Medium) findings; brutal-floor / hard-to-exploit-excluding programs
    are worth less."""
    if policy is None:
        return 1.0
    by_floor = {0: 1.15, 1: 1.0, 2: 0.8, 3: 0.5, 4: 0.3, 5: 0.2}
    factor = by_floor.get(sev_rank(policy.min_severity), 1.0)
    if policy.excludes_hard_to_exploit:
        factor *= 0.7
    return factor


def acceptance_factor(policy: RewardPolicy | None) -> float:
    """How likely a *typical* (often Medium / hard-to-exploit) finding is accepted,
    given the program's floor. Feeds the portfolio model's p_accepted."""
    if policy is None:
        return 1.0
    by_floor = {0: 1.0, 1: 0.9, 2: 0.7, 3: 0.4, 4: 0.2, 5: 0.1}
    factor = by_floor.get(sev_rank(policy.min_severity), 0.7)
    if policy.excludes_hard_to_exploit:
        factor *= 0.6
    return factor


def accept_probability(base: float, policy: RewardPolicy | None) -> float:
    """Base acceptance prior scaled by the program's reward floor, clamped to [0,1]."""
    return max(0.0, min(1.0, base * acceptance_factor(policy)))


def eligibility(severity: str, hard_to_exploit: bool, policy: RewardPolicy | None) -> str:
    """Human-readable submit/skip verdict for a finding against a program's policy."""
    if policy is None:
        return "no reward policy on file — check the program page before submitting"
    if hard_to_exploit and policy.excludes_hard_to_exploit:
        return f"LIKELY OUT OF SCOPE — {policy.handle} excludes hard-to-exploit bugs ($0)"
    if not meets_floor(severity, policy):
        return f"LIKELY OUT OF SCOPE — below {policy.handle}'s reward floor (min {policy.min_severity})"
    return f"eligible — clears {policy.handle}'s floor (min {policy.min_severity})"
