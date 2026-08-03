"""Automatic program selection.

You shouldn't have to name a program. Given the HackerOne account's authorized
programs, this inspects them and keeps only the ones actually worth hunting for a
*code* scanner — open for submissions, automation + AI permitted, and carrying
in-scope source-code repos — then ranks them (bounty programs and more repos first)
and returns the top few. The hunter runs on whatever this picks.

It reads only; it applies the same scope gate as the pipeline, so it can never
select a program that forbids automated/AI tooling.
"""

from __future__ import annotations

from dataclasses import dataclass

from aegis.ingest.hackerone import map_program
from aegis.integrations.repo_pipeline import repos_in_scope


@dataclass(frozen=True)
class ProgramCandidate:
    handle: str
    name: str
    offers_bounties: bool
    repo_count: int
    score: float


def select_programs(h1_client, *, want: int = 3, inspect_limit: int = 20,
                    prefer_bounties: bool = True, skip_handles=()) -> list[ProgramCandidate]:
    """Inspect up to ``inspect_limit`` authorized programs; return the top ``want``
    that a code scanner can actually work on (gated, ranked)."""
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
            continue                                  # not accepting reports
        scope = repos_in_scope(rules)                 # applies the automation/AI gate
        if scope.gated or not scope.repos:
            continue
        score = len(scope.repos) + (2.0 if (prefer_bounties and rules.offers_bounties) else 0.0)
        candidates.append(ProgramCandidate(
            handle=rules.handle or handle, name=rules.name,
            offers_bounties=rules.offers_bounties, repo_count=len(scope.repos), score=score))

    candidates.sort(key=lambda c: (c.score, c.repo_count), reverse=True)
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
