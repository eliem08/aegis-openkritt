"""Net-profit allocation for authorized source-code bug-bounty research.

Target ranking and finding escalation now share the same ``portfolio_agents.Opportunity``
probability/cost contract. ``ProfitEstimate`` remains the stable compatibility/result shape
used by AutoHunter and the UI; it no longer owns a second net-EV equation.
"""

from __future__ import annotations

from dataclasses import dataclass

from aegis.scheduler.profit import HuntOpportunity

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
    """Legacy gross score retained for API/test compatibility."""
    return round(expected_value(target, config or AutoHuntConfig()) * class_fit(target), 2)


def projected_cost(target: HuntTarget, config: AutoHuntConfig | None = None) -> float:
    cfg = config or AutoHuntConfig()
    return round(target_opportunity(target, cfg).total_cost(cfg.human_hourly_cost_usd), 2)


def target_opportunity(
    target: HuntTarget,
    config: AutoHuntConfig | None = None,
    *,
    feedback_factor: float = 1.0,
    include_duplicate_risk: bool = True,
) -> HuntOpportunity:
    """Adapt a target into the common portfolio opportunity model.

    Competition/saturation reduces the chance that a useful unique bug remains. Class fit and
    historical feedback adjust the payout basis rather than creating a second EV formula.
    ``p_reproducible`` is left at 1.0 at target-allocation time because no finding exists yet;
    finding-level Jarvis economics supplies an evidence-based value later.
    """
    cfg = config or AutoHuntConfig()
    crowd = 1.0 - _bounded(target.saturation)
    fit = class_fit(target)
    feedback = min(2.0, max(0.25, float(feedback_factor or 1.0)))
    raw_payout = realistic_payout(target, config=cfg)
    payout = float(raw_payout) * fit * feedback if raw_payout > 0 else None
    compute = target.estimated_compute_cost_usd or cfg.default_compute_cost_usd
    review_minutes = target.human_review_minutes or cfg.default_human_review_minutes
    unique = 1.0 - _bounded(target.duplicate_risk) if include_duplicate_risk else 1.0
    p_find = _bounded(target.findability) * crowd * crowd
    return HuntOpportunity(
        opportunity_id=f"target:{target.handle or target.repository}:{target.repository}",
        program_id=target.handle or target.repository,
        program_handle=target.handle,
        asset_id=f"repository:{target.repository}",
        asset_kind="source_code",
        asset_locator=target.repository,
        attack_surface="source",
        weakness_family="target_allocation",
        estimated_payout_usd=payout,
        p_find=p_find,
        p_valid=_bounded(cfg.p_valid),
        p_accepted=_bounded(cfg.p_accept),
        p_unique=unique,
        p_reproducible=1.0,
        compute_cost_usd=max(0.0, float(compute)),
        model_cost_usd=0.0,
        expected_human_minutes=max(0.0, float(review_minutes)),
        opportunity_cost_usd=0.0,
        information_gain=max(0.0, _bounded(target.findability) * crowd),
        uncertainty=max(0.0, 1.0 - p_find),
        provenance=("aegis.ai.profit.target_opportunity",),
    )


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
    opportunity = target_opportunity(target, cfg, feedback_factor=feedback_factor)
    gross_opportunity = target_opportunity(
        target,
        cfg,
        feedback_factor=feedback_factor,
        include_duplicate_risk=False,
    )
    gross = gross_opportunity.gross_value()
    duplicate_adjusted = opportunity.gross_value()
    cost = opportunity.total_cost(cfg.human_hourly_cost_usd)
    net = opportunity.expected_value(cfg.human_hourly_cost_usd)
    roi = net / cost if cost > 0 else (100.0 if net > 0 else 0.0)
    payout = float(realistic_payout(target, config=cfg))
    return ProfitEstimate(
        payout_basis=payout,
        gross_ev=round(gross, 2),
        duplicate_adjusted_ev=round(duplicate_adjusted, 2),
        projected_cost_usd=round(cost, 2),
        net_ev=round(net, 2),
        roi=round(roi, 2),
        duplicate_risk=_bounded(target.duplicate_risk),
        class_fit=class_fit(target),
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
