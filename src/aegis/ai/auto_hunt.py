"""Autonomous, profit-ranked hunting for the code/contract lanes.

The orchestrator is deliberately deterministic: it ranks authorized source targets,
applies projected-cost and net-EV gates, invokes an injected hunt function, and records
candidate/validation counts. It never submits reports and never performs live testing.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass
class HuntTarget:
    repository: str
    handle: str = ""
    reward_ceiling: float = 0.0
    findability: float = 0.5
    subpath: str = ""
    kind: str = "repo"
    saturation: float = 0.0
    likely_payout: float = 0.0
    estimated_compute_cost_usd: float = 0.0
    human_review_minutes: int = 0
    duplicate_risk: float = 0.0


@dataclass
class HuntOutcome:
    """What the injected hunt function returns for one target.

    ``confirmed`` is reserved for findings that passed the validation lane. A defensive
    post-init guard recognizes the explicit scanners-only result shape (every finding is tagged
    ``origin=scanner|skill`` and lacks validator/economics fields) and moves those counts back to
    ``candidates``. Generic injected/test outcomes are not reinterpreted.
    """

    target: HuntTarget
    candidates: int = 0
    confirmed: int = 0
    unresolved: int = 0
    rejected: int = 0
    poc_dir: str = ""
    error: str = ""
    findings: list[dict] = field(default_factory=list)
    scanner_candidates: int = 0
    skill_candidates: int = 0
    tools_run: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.confirmed or not self.findings:
            return
        scanner_only_shape = all(
            f.get("origin") in {"scanner", "skill"}
            and f.get("reproduction") is None
            and "expected_gain" not in f
            and "agreement" not in f
            and "cvss" not in f
            for f in self.findings
        )
        if scanner_only_shape:
            self.candidates = max(self.candidates, self.confirmed, len(self.findings))
            self.confirmed = 0


@dataclass
class AutoHuntConfig:
    max_targets: int = 5
    samples: int = 3
    min_ev: float = 0.0
    hint: str = ""
    p_valid: float = 0.30
    p_accept: float = 0.60
    profit_first: bool = True
    min_net_ev: float = 0.0
    max_projected_spend_usd: float = 0.0
    human_hourly_cost_usd: float = 20.0
    default_compute_cost_usd: float = 2.0
    default_human_review_minutes: int = 15
    payout_fraction: float = 0.30
    feedback_by_handle: dict[str, float] = field(default_factory=dict)


def expected_value(target: HuntTarget, config: AutoHuntConfig) -> float:
    """Legacy gross EV using the advertised reward ceiling."""
    crowd = 1.0 - min(1.0, max(0.0, target.saturation))
    return round(
        max(0.0, target.findability)
        * crowd * crowd
        * config.p_valid
        * config.p_accept
        * max(0.0, target.reward_ceiling),
        2,
    )


def rank_targets(targets: list[HuntTarget], config: AutoHuntConfig) -> list[tuple[HuntTarget, float]]:
    scored = [(target, expected_value(target, config)) for target in targets]
    scored = [(target, ev) for target, ev in scored if ev >= config.min_ev]
    scored.sort(key=lambda row: (-row[1], row[0].repository))
    return scored


@dataclass
class AutoHuntSession:
    ranked: list[dict] = field(default_factory=list)
    outcomes: list[HuntOutcome] = field(default_factory=list)
    status: str = "running"
    projected_spend_usd: float = 0.0
    projected_net_ev: float = 0.0

    @property
    def confirmed_total(self) -> int:
        return sum(outcome.confirmed for outcome in self.outcomes)

    @property
    def candidate_total(self) -> int:
        return sum(outcome.candidates for outcome in self.outcomes)

    def summary(self) -> dict:
        return {
            "status": self.status,
            "targets_ranked": len(self.ranked),
            "targets_hunted": len(self.outcomes),
            "candidate_total": self.candidate_total,
            "confirmed_total": self.confirmed_total,
            "projected_spend_usd": round(self.projected_spend_usd, 2),
            "projected_net_ev": round(self.projected_net_ev, 2),
            "ranked": self.ranked,
            "results": [
                {
                    "repository": outcome.target.repository,
                    "handle": outcome.target.handle,
                    "candidates": outcome.candidates,
                    "confirmed": outcome.confirmed,
                    "unresolved": outcome.unresolved,
                    "rejected": outcome.rejected,
                    "poc_dir": outcome.poc_dir,
                    "error": outcome.error,
                    "scanner_candidates": outcome.scanner_candidates,
                    "skill_candidates": outcome.skill_candidates,
                    "tools_run": outcome.tools_run,
                    "findings": outcome.findings,
                }
                for outcome in self.outcomes
            ],
        }


class AutoHunter:
    """Run only targets that clear value and projected-spend gates."""

    def __init__(
        self,
        hunt_fn: Callable[[HuntTarget, int], HuntOutcome],
        *,
        config: AutoHuntConfig | None = None,
        on_event: Callable[[str, dict], None] | None = None,
    ) -> None:
        self._hunt = hunt_fn
        self._config = config or AutoHuntConfig()
        self._on_event = on_event or (lambda *_: None)

    def run(self, targets: list[HuntTarget]) -> AutoHuntSession:
        config = self._config
        rows: list[tuple[HuntTarget, float, dict]] = []

        if config.profit_first:
            from .profit import rank_by_net_profit

            for target, estimate in rank_by_net_profit(
                targets, config, feedback_by_handle=config.feedback_by_handle
            ):
                if estimate.gross_ev < config.min_ev or estimate.net_ev < config.min_net_ev:
                    continue
                rows.append((target, estimate.net_ev, estimate.as_dict()))
        else:
            for target, ev in rank_targets(targets, config):
                rows.append(
                    (
                        target,
                        ev,
                        {
                            "gross_ev": ev,
                            "net_ev": ev,
                            "projected_cost_usd": 0.0,
                            "roi": 0.0,
                        },
                    )
                )

        session = AutoHuntSession(
            ranked=[
                {
                    "repository": target.repository,
                    "handle": target.handle,
                    "ev": details.get("gross_ev", score),
                    "net_ev": details.get("net_ev", score),
                    "projected_cost_usd": details.get("projected_cost_usd", 0.0),
                    "roi": details.get("roi", 0.0),
                    "findability": target.findability,
                    "reward_ceiling": target.reward_ceiling,
                }
                for target, score, details in rows
            ]
        )
        self._on_event("ranked", {"count": len(rows), "profit_first": config.profit_first})

        for index, (target, score, details) in enumerate(rows[: config.max_targets], start=1):
            next_cost = float(details.get("projected_cost_usd", 0.0) or 0.0)
            cap = max(0.0, float(config.max_projected_spend_usd or 0.0))
            if cap and session.projected_spend_usd + next_cost > cap:
                session.status = "budget_exhausted"
                self._on_event(
                    "projected_budget_stop",
                    {
                        "repository": target.repository,
                        "projected_spend": round(session.projected_spend_usd, 2),
                        "next_cost": round(next_cost, 2),
                        "session_cap": round(cap, 2),
                    },
                )
                break

            self._on_event(
                "hunt_start",
                {
                    "n": index,
                    "repository": target.repository,
                    "ev": details.get("gross_ev", score),
                    "net_ev": details.get("net_ev", score),
                    "projected_cost_usd": next_cost,
                },
            )
            try:
                outcome = self._hunt(target, config.samples)
            except Exception as exc:
                outcome = HuntOutcome(target=target, error=f"{type(exc).__name__}: {exc}"[:200])
            session.outcomes.append(outcome)
            session.projected_spend_usd += next_cost
            session.projected_net_ev += float(details.get("net_ev", score) or 0.0)
            self._on_event(
                "hunt_done",
                {
                    "n": index,
                    "repository": target.repository,
                    "candidates": outcome.candidates,
                    "confirmed": outcome.confirmed,
                    "error": outcome.error,
                    "scanner_candidates": outcome.scanner_candidates,
                    "skill_candidates": outcome.skill_candidates,
                    "tools_run": outcome.tools_run,
                },
            )

        if session.status == "running":
            session.status = "completed"
        self._on_event("completed", session.summary())
        return session
