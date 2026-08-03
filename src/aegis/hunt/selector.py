"""Automatic, profit-aware program selection.

You shouldn't have to name a program, and the hunter shouldn't waste effort where
there's no money. Given the account's authorized programs, this inspects them and
keeps only the ones worth a code scanner's time — open for submissions, automation +
AI permitted, and carrying **bounty-eligible** in-scope source-code repos — then
ranks them by expected profitability and returns the top few.

HackerOne's Hacker API exposes no dollar amounts, so profitability is read from the
signals it *does* give per scope: whether the asset is ``eligible_for_bounty`` and
its ``max_severity`` (the payout ceiling — critical pays the top tier, low barely
pays). It reads only, and applies the same automation/AI gate as the pipeline, so it
can never select a program that forbids automated tooling.
"""

from __future__ import annotations

from dataclasses import dataclass

from aegis.ingest.hackerone import map_program
from aegis.integrations.repo_pipeline import repos_in_scope

from .reward import DEFAULT_REWARD_POLICIES, reward_factor, sev_rank

# Payout-ceiling weight by scope max_severity. Unknown -> medium (don't zero it out).
_SEVERITY_WEIGHT = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0, "none": 0.0}


def _severity_weight(sev: str) -> float:
    return _SEVERITY_WEIGHT.get(str(sev or "").strip().lower(), 2.0)


@dataclass(frozen=True)
class ProgramCandidate:
    handle: str
    name: str
    offers_bounties: bool
    repo_count: int              # bounty-eligible code repos considered
    top_severity: str            # highest payout ceiling among them
    profitability: float         # reward-adjusted, severity-weighted score
    reward_floor: str = "low"    # lowest severity the program actually pays
    reward_note: str = ""        # why (from the reward policy overlay)


def select_programs(h1_client, *, want: int = 3, inspect_limit: int = 20,
                    require_bounty: bool = True, skip_handles=(),
                    reward_policies=None) -> list[ProgramCandidate]:
    """Inspect up to ``inspect_limit`` authorized programs; return the top ``want``
    by REWARD-ADJUSTED profitability. ``require_bounty`` drops programs with no
    bounty-eligible code; programs whose severity ceiling can't clear their reward
    floor are dropped, and high-floor / hard-to-exploit-excluding programs are
    deprioritized (so we don't chase targets whose realistic findings won't pay)."""
    policies = DEFAULT_REWARD_POLICIES if reward_policies is None else reward_policies
    skip = {str(h).lower() for h in skip_handles}
    candidates: list[ProgramCandidate] = []
    for program in (h1_client.list_programs() or [])[:inspect_limit]:
        handle = _handle(program)
        if not handle or handle.lower() in skip:
            continue
        try:
            rules = _rules(h1_client, handle)
        except Exception:
            continue                                  # unreadable program -> skip, keep going
        if rules.submission_state and rules.submission_state != "open":
            continue
        scope = repos_in_scope(rules)                 # applies the automation/AI gate
        if scope.gated or not scope.repos:
            continue

        bounty_repos = [r for r in scope.repos if r.eligible_for_bounty]
        if require_bounty and not bounty_repos:
            continue                                  # no payout here -> not profitable
        rated = bounty_repos or scope.repos
        top = max(rated, key=lambda r: _severity_weight(r.max_severity)).max_severity

        policy = policies.get(rules.handle or handle)
        # ceiling can't even reach the reward floor -> can never pay, drop it
        if policy and sev_rank(top) < sev_rank(policy.min_severity):
            continue
        raw = sum(_severity_weight(r.max_severity) for r in rated)
        profitability = raw * reward_factor(policy)     # reward-adjusted
        candidates.append(ProgramCandidate(
            handle=rules.handle or handle, name=rules.name,
            offers_bounties=bool(bounty_repos), repo_count=len(rated),
            top_severity=top or "unspecified", profitability=round(profitability, 2),
            reward_floor=policy.min_severity if policy else "low",
            reward_note=policy.notes if policy else ""))

    candidates.sort(key=lambda c: (c.profitability, _severity_weight(c.top_severity),
                                   c.repo_count), reverse=True)
    return candidates[:want]


def _handle(program) -> str:
    if not isinstance(program, dict):
        return ""
    attrs = program.get("attributes") or {}
    return str(attrs.get("handle") or program.get("id") or "")


def _rules(h1_client, handle: str):
    program = h1_client.get_program(handle)
    scopes = h1_client.get_structured_scopes(handle)
    return map_program(program, scopes)
