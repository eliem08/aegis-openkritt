"""Autonomous, profit-ranked hunting for the code/contract lanes.

Ties together the pieces built this session into one loop: rank candidate targets by
expected value (findability × reward, so effort goes where money is likeliest), run the
full hunt on the best ones within a budget, collect confirmed findings, scaffold PoCs,
and record every verdict back into the learning store.

Boundaries this loop keeps, by construction:
* Code/contract lanes only — it clones and reads published source. It never tests a
  live third-party system.
* It produces CANDIDATES + PoC scaffolds surfaced for review. It never submits to a
  bounty program — a human approves and submits.

The hunt function is injected, so the orchestration is deterministic and testable
without touching the network or a model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass
class HuntTarget:
    repository: str                 # owner/repo, or a 0x… contract address
    handle: str = ""                # HackerOne program handle
    reward_ceiling: float = 0.0     # top payout for the program (USD)
    findability: float = 0.5        # 0..1 softness (from saturation.findability)
    subpath: str = ""               # optional focus subtree
    kind: str = "repo"              # "repo" | "contract"
    saturation: float = 0.0         # 0..1 how picked-over the program is (fame/hunter density);
    #                                 higher = more competition, discounts EV quadratically


@dataclass
class HuntOutcome:
    """What the injected hunt function returns for one target."""
    target: HuntTarget
    confirmed: int = 0
    unresolved: int = 0
    rejected: int = 0
    poc_dir: str = ""
    error: str = ""
    findings: list[dict] = field(default_factory=list)   # confirmed finding summaries
    scanner_candidates: int = 0   # raw findings folded in from OSS scanners (pre-validation)
    skill_candidates: int = 0     # raw findings folded in from arm's-length skills
    tools_run: list[str] = field(default_factory=list)   # which scanners/skills actually ran


@dataclass
class AutoHuntConfig:
    max_targets: int = 5            # cost ceiling: how many targets to hunt this run
    samples: int = 3               # generator ensemble size per file
    min_ev: float = 0.0            # skip targets below this expected value
    hint: str = ""                 # operator lead seeded into every target's generator
    p_valid: float = 0.30          # P(a found candidate is actually valid) — prior
    p_accept: float = 0.60         # P(a valid finding is accepted/paid) — prior


def expected_value(target: HuntTarget, config: AutoHuntConfig) -> float:
    """EV(target) = findability × (1-saturation)² × P(valid) × P(accept) × reward_ceiling.

    findability stands in for P(we surface something); the two priors discount to what
    is actually paid; reward_ceiling scales by the money on offer. The saturation term
    is the "don't chase the overcrowded stuff" penalty: a famous, heavily-hunted program
    (saturation→1) is discounted quadratically, so a big reward ceiling can no longer
    float a target that every top hunter is already on. Deterministic."""
    crowd = 1.0 - min(1.0, max(0.0, target.saturation))
    return round(max(0.0, target.findability) * (crowd * crowd)
                 * config.p_valid * config.p_accept
                 * max(0.0, target.reward_ceiling), 2)


def rank_targets(targets: list[HuntTarget], config: AutoHuntConfig) -> list[tuple[HuntTarget, float]]:
    """Targets by descending expected value, dropping those below ``min_ev``."""
    scored = [(t, expected_value(t, config)) for t in targets]
    scored = [(t, ev) for t, ev in scored if ev >= config.min_ev]
    scored.sort(key=lambda te: (-te[1], te[0].repository))
    return scored


@dataclass
class AutoHuntSession:
    ranked: list[dict] = field(default_factory=list)
    outcomes: list[HuntOutcome] = field(default_factory=list)
    status: str = "running"

    @property
    def confirmed_total(self) -> int:
        return sum(o.confirmed for o in self.outcomes)

    def summary(self) -> dict:
        return {
            "status": self.status,
            "targets_ranked": len(self.ranked),
            "targets_hunted": len(self.outcomes),
            "confirmed_total": self.confirmed_total,
            "ranked": self.ranked,
            "results": [
                {"repository": o.target.repository, "handle": o.target.handle,
                 "confirmed": o.confirmed, "unresolved": o.unresolved,
                 "rejected": o.rejected, "poc_dir": o.poc_dir, "error": o.error,
                 "scanner_candidates": o.scanner_candidates,
                 "skill_candidates": o.skill_candidates, "tools_run": o.tools_run,
                 "findings": o.findings}
                for o in self.outcomes
            ],
        }


class AutoHunter:
    """Rank targets by EV and hunt the best within budget, collecting candidates.

    ``hunt_fn(target, samples) -> HuntOutcome`` does the actual clone→hunt→validate→PoC
    for one target; injecting it keeps this loop testable and its boundaries explicit
    (the loop itself never touches a network or a live system)."""

    def __init__(self, hunt_fn: Callable[[HuntTarget, int], HuntOutcome], *,
                 config: AutoHuntConfig | None = None,
                 on_event: Callable[[str, dict], None] | None = None) -> None:
        self._hunt = hunt_fn
        self._config = config or AutoHuntConfig()
        self._on_event = on_event or (lambda *_: None)

    def run(self, targets: list[HuntTarget]) -> AutoHuntSession:
        config = self._config
        ranked = rank_targets(targets, config)
        session = AutoHuntSession(
            ranked=[{"repository": t.repository, "handle": t.handle, "ev": ev,
                     "findability": t.findability, "reward_ceiling": t.reward_ceiling}
                    for t, ev in ranked]
        )
        self._on_event("ranked", {"count": len(ranked)})
        for index, (target, ev) in enumerate(ranked[: config.max_targets], start=1):
            self._on_event("hunt_start",
                           {"n": index, "repository": target.repository, "ev": ev})
            try:
                outcome = self._hunt(target, config.samples)
            except Exception as exc:                     # one bad target must not sink the run
                outcome = HuntOutcome(target=target, error=f"{type(exc).__name__}: {exc}"[:200])
            session.outcomes.append(outcome)
            self._on_event("hunt_done",
                           {"n": index, "repository": target.repository,
                            "confirmed": outcome.confirmed, "error": outcome.error,
                            "scanner_candidates": outcome.scanner_candidates,
                            "skill_candidates": outcome.skill_candidates,
                            "tools_run": outcome.tools_run})
        session.status = "completed"
        self._on_event("completed", session.summary())
        return session
