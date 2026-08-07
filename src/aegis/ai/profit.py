"""Net-profit allocation for authorized source-code bug-bounty research.

The score is an allocation heuristic, not an earning guarantee. It uses a realistic payout,
duplicate risk, target competition, class fit, model/scanner cost, and analyst-review cost.
"""

from __future__ import annotations

from dataclasses import dataclass

from .auto_hunt import AutoHuntConfig, HuntTarget, expected_value

_EXT_FIT = {
    ".sol": 1.35,
    ".php": 1.20,
    ".rb": 1.10,
    ".py": 1.00,
    ".js": 1.00,
    ".ts": 1.00,
    ".go": 0.95,
    ".java": 0.95,
    ".rs": 0.95,
}
_CONTRACT_FIT = 1.35
_PAYOUT_FRACTION = {"critical": 0.35, "high": 0.30, "medium": 0.25, "low": 0.20, "none": 0.0}


def _bounded(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return min(high, max(low, float(value)))


def _repo_ext(repo: str, kind: str) -> str:
    if kind == "contract":
        return ".sol"
    lowered = repo.lower()
    for ext, hints in (
        (".sol", ("solidity",)),
        (".php", ("wordpress", "wp-", "php", "mainwp", "matomo", "wordpoints")),
        (".rb", ("rails", "ruby", "-rb", "identity-")),
        (".go", ("go-", "-go", "fabric", "nebula")),
        (".py", ("airflow", "python")),
    ):
        if any(hint in lowered for hint in hints):
            return ext
    return ""


def class_fit(target: HuntTarget) -> float:
    if target.kind == "contract":
        return _CONTRACT_FIT
    return _EXT_FIT.get(_repo_ext(target.repository, target.kind), 0.90)


def realistic_payout(
    target: HuntTarget,
    severity_floor: str = "critical",
    config: AutoHuntConfig | None = None,
) -> int:
    if target.likely_payout > 0:
        return int(round(target.likely_payout))
    fraction = (
        _bounded(config.payout_fraction)
        if config is not None
        else _PAYOUT_FRACTION.get((severity_floor or "critical").lower(), 0.25)
    )
    return int(round(max(0.0, target.reward_ceiling) * fraction))


def expected_profit(
    target: HuntTarget,
    config: AutoHuntConfig | None = None,
    severity_floor: str = "critical",
) -> float:
    """Legacy gross score retained for compatibility."""
    return round(expected_value(target, config or AutoHuntConfig()) * class_fit(target), 2)


def projected_cost(target: HuntTarget, config: AutoHuntConfig | None = None) -> float:
    cfg = config or AutoHuntConfig()
    compute = target.estimated_compute_cost_usd or cfg.default_compute_cost_usd
    review_minutes = target.human_review_minutes or cfg.default_human_review_minutes
    analyst_cost = max(0, review_minutes) / 60.0 * max(0.0, cfg.human_hourly_cost_usd)
    return round(max(0.0, compute) + analyst_cost, 2)


@dataclass(frozen=True)
class ProfitEstimate:
    payout_basis: float
    gross_ev: float
    duplicate_adjusted_ev: float
    projected_cost_usd: float
    net_ev: float
    roi: float
    duplicate_risk: float
    class_fit: float

    def as_dict(self) -> dict:
        return {
            "payout_basis": round(self.payout_basis, 2),
            "gross_ev": round(self.gross_ev, 2),
            "duplicate_adjusted_ev": round(self.duplicate_adjusted_ev, 2),
            "projected_cost_usd": round(self.projected_cost_usd, 2),
            "net_ev": round(self.net_ev, 2),
            "roi": round(self.roi, 2),
            "duplicate_risk": round(self.duplicate_risk, 3),
            "class_fit": round(self.class_fit, 2),
        }


def estimate_profit(
    target: HuntTarget,
    config: AutoHuntConfig | None = None,
    *,
    feedback_factor: float = 1.0,
) -> ProfitEstimate:
    cfg = config or AutoHuntConfig()
    crowd = 1.0 - _bounded(target.saturation)
    fit = class_fit(target)
    payout = float(realistic_payout(target, config=cfg))
    gross = (
        _bounded(target.findability)
        * crowd * crowd
        * _bounded(cfg.p_valid)
        * _bounded(cfg.p_accept)
        * payout
        * fit
    )
    gross *= min(2.0, max(0.25, float(feedback_factor or 1.0)))
    duplicate_risk = _bounded(target.duplicate_risk)
    duplicate_adjusted = gross * (1.0 - duplicate_risk)
    cost = projected_cost(target, cfg)
    net = duplicate_adjusted - cost
    roi = net / cost if cost > 0 else (100.0 if net > 0 else 0.0)
    return ProfitEstimate(
        payout_basis=payout,
        gross_ev=round(gross, 2),
        duplicate_adjusted_ev=round(duplicate_adjusted, 2),
        projected_cost_usd=cost,
        net_ev=round(net, 2),
        roi=round(roi, 2),
        duplicate_risk=duplicate_risk,
        class_fit=fit,
    )


def rank_by_profit(
    targets: list[HuntTarget], config: AutoHuntConfig | None = None
) -> list[tuple[HuntTarget, float, int]]:
    scored = [
        (target, expected_profit(target, config), realistic_payout(target, config=config))
        for target in targets
    ]
    scored.sort(key=lambda row: (-row[1], -row[2]))
    return scored


def rank_by_net_profit(
    targets: list[HuntTarget],
    config: AutoHuntConfig | None = None,
    *,
    feedback_by_handle: dict[str, float] | None = None,
) -> list[tuple[HuntTarget, ProfitEstimate]]:
    feedback = feedback_by_handle or {}
    scored = [
        (
            target,
            estimate_profit(target, config, feedback_factor=feedback.get(target.handle, 1.0)),
        )
        for target in targets
    ]
    scored.sort(
        key=lambda row: (
            -row[1].net_ev,
            -row[1].roi,
            -row[1].payout_basis,
            row[0].repository,
        )
    )
    return scored


def main(argv=None) -> int:
    import sys

    from .auto_hunt_run import build_targets_from_ranking

    path = argv[0] if argv else (
        sys.argv[1] if len(sys.argv) > 1 else "reports/autohunt_targets_full.json"
    )
    ranked = rank_by_net_profit(build_targets_from_ranking(path))
    print(f"{'NET_EV':>9}  {'GROSS':>8}  {'COST':>7}  {'ROI':>6}  {'PAYOUT':>8}  TARGET")
    for target, estimate in ranked[:25]:
        print(
            f"{estimate.net_ev:>9.1f}  {estimate.gross_ev:>8.1f}  "
            f"{estimate.projected_cost_usd:>7.2f}  {estimate.roi:>6.1f}  "
            f"{estimate.payout_basis:>8,.0f}  {target.repository}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
