"""Expected-profit ranking: point the budget at the targets that actually pay.

The base EV (auto_hunt.expected_value) already discounts by findability and saturation.
This adds the two levers that matter for *profit specifically*:

  1. class-fit — how well a target's likely bug classes match what Aegis is demonstrably
     good at AND what actually pays. Access-control/IDOR dominates real disclosed reports;
     the contract lane + 0xSimao corpus make DeFi (Solidity) the highest-ceiling lane;
     PHP/Rails have strong dedicated scanners (psalm taint, brakeman). Language/kind is a
     cheap proxy for this.
  2. realistic payout — most accepted bugs pay well below the program ceiling. Report a
     realistic band (a fraction of ceiling), not the headline number.

Deterministic and honest: it re-ranks the queue you already have and states realistic
dollars. The biggest profit lever it CANNOT supply is scope — feeding in high-ceiling,
in-scope DeFi/web3 contract addresses (the contract lane) beats any reshuffle of picked-
over web repos.
"""

from __future__ import annotations

from pathlib import Path

from .auto_hunt import AutoHuntConfig, HuntTarget, expected_value

# language/kind -> class-fit multiplier (Aegis strength x payout of that lane)
_EXT_FIT = {
    ".sol": 1.35,   # contracts: strongest lane (slither+mythril+property+corpus), top ceilings
    ".php": 1.20,   # psalm taint + access-control-heavy CMS/plugin ecosystem
    ".rb": 1.10,    # brakeman; Rails access-control/injection
    ".py": 1.00, ".js": 1.00, ".ts": 1.00,
    ".go": 0.95, ".java": 0.95, ".rs": 0.95,
}
_CONTRACT_FIT = 1.35

# what fraction of the ceiling a typical *accepted* finding actually pays, by floor
_PAYOUT_FRACTION = {"critical": 0.35, "high": 0.30, "medium": 0.25, "low": 0.20, "none": 0.0}


def _repo_ext(repo: str, kind: str) -> str:
    if kind == "contract":
        return ".sol"
    # crude language guess from common repo-name hints; falls back to unknown
    r = repo.lower()
    for ext, hint in ((".sol", "solidity"), (".php", ("wordpress", "wp-", "php", "mainwp",
                       "matomo", "wordpoints")), (".rb", ("rails", "ruby", "-rb", "identity-")),
                      (".go", ("go-", "-go", "fabric", "nebula")), (".py", ("py", "airflow"))):
        hints = hint if isinstance(hint, tuple) else (hint,)
        if any(h in r for h in hints):
            return ext
    return ""


def class_fit(target: HuntTarget) -> float:
    if target.kind == "contract":
        return _CONTRACT_FIT
    return _EXT_FIT.get(_repo_ext(target.repository, target.kind), 0.90)


def realistic_payout(target: HuntTarget, severity_floor: str = "critical") -> int:
    frac = _PAYOUT_FRACTION.get((severity_floor or "critical").lower(), 0.25)
    return int(round(target.reward_ceiling * frac))


def expected_profit(target: HuntTarget, config: AutoHuntConfig | None = None,
                    severity_floor: str = "critical") -> float:
    """Base EV x class-fit — the profit-optimised score."""
    ev = expected_value(target, config or AutoHuntConfig())
    return round(ev * class_fit(target), 2)


def rank_by_profit(targets: list[HuntTarget], config: AutoHuntConfig | None = None
                   ) -> list[tuple[HuntTarget, float, int]]:
    """(target, expected_profit, realistic_payout$), most profitable first."""
    scored = [(t, expected_profit(t, config), realistic_payout(t)) for t in targets]
    scored.sort(key=lambda s: (-s[1], -s[2]))
    return scored


def main(argv=None) -> int:
    import json
    import sys

    from .auto_hunt_run import build_targets_from_ranking
    path = argv[0] if argv else (sys.argv[1] if len(sys.argv) > 1
                                 else "reports/autohunt_targets_full.json")
    targets = build_targets_from_ranking(path)
    ranked = rank_by_profit(targets)
    print(f"{'PROFIT':>8}  {'PAYOUT$':>8}  {'FIT':>4}  {'CROWD':>5}  TARGET")
    for t, profit, payout in ranked[:25]:
        print(f"{profit:>8.1f}  {payout:>8,}  {class_fit(t):>4.2f}  "
              f"{int(t.saturation*100):>4}%  {t.repository}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
