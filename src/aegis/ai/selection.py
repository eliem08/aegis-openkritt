"""Target-selection scoring — decide what to hunt BEFORE spending a run on it.

mdp_sec's hardest-won number: *~80% of completed targets produced no report*, and *"running
faster does not help much if I keep choosing the wrong targets."* The SSV run was that exact
mistake — a multiply-audited, years-live protocol where a fresh automated pass was never
likely to pay. Speed doesn't fix target choice; scoring does.

This layers a *maturity discount* on top of the existing expected-profit score
(`profit.expected_profit`, which already accounts for reward, findability and crowd
saturation). The new lever is what saturation alone misses: how hard the target has already
been looked at.

  maturity_discount = audit_factor × age_factor × history_factor   (each in (0,1])

  * audit_factor   — every prior professional audit shrinks the odds a novel bug remains.
  * age_factor     — a long-live protocol has survived more eyes than a fresh launch.
  * history_factor — many already-paid reports means the easy surface is gone.

A fresh, unaudited, few-reports target keeps ~full score; an SSV-shaped one is pushed far
down. Deterministic and explainable — it prints WHY each target ranks where it does, so the
operator (who still makes the final call) can see the reasoning, not just a number.
"""

from __future__ import annotations

from dataclasses import dataclass

from .profit import expected_profit, realistic_payout


def _audit_factor(audits: int) -> float:
    # 0 audits -> 1.0; each audit multiplies remaining novel-bug odds by ~0.7, floored so a
    # heavily-audited target is discounted hard but never to exactly zero.
    return max(0.15, 0.7 ** max(0, int(audits)))


def _age_factor(age_months: int) -> float:
    # fresh (<3mo) -> 1.0; decays ~linearly to a 0.4 floor around 3 years live.
    m = max(0, int(age_months))
    if m <= 3:
        return 1.0
    return max(0.40, 1.0 - (m - 3) * (0.6 / 33))


def _history_factor(paid_reports: int) -> float:
    # no paid reports -> 1.0; each ~10 paid reports knocks off a chunk, 0.3 floor.
    return max(0.30, 1.0 - min(0.70, max(0, int(paid_reports)) / 100.0))


def maturity_discount(audits: int = 0, age_months: int = 0, paid_reports: int = 0) -> float:
    """Combined (0,1] discount — 1.0 for a pristine target, small for a picked-over one."""
    return round(_audit_factor(audits) * _age_factor(age_months) * _history_factor(paid_reports), 4)


@dataclass
class Scored:
    program: object            # registry.Program
    target: object             # auto_hunt.HuntTarget
    base_profit: float         # profit.expected_profit
    discount: float            # maturity_discount
    yield_score: float         # base_profit × discount — the ranking key
    payout: int                # realistic $ if it lands

    def why(self) -> str:
        p = self.program
        return (f"audits={p.audits}·age={p.age_months}mo·paid={p.paid_reports} "
                f"-> discount {self.discount:.2f}; base {self.base_profit:.1f} "
                f"-> yield {self.yield_score:.1f}")


def score_programs(programs: list, config=None) -> list[Scored]:
    """Rank active programs by yield_score (expected_profit × maturity_discount), best first.

    Each program expands to its in-scope targets; the program's maturity fields discount the
    per-target profit. Inactive programs are dropped."""
    from .registry import to_hunt_targets
    by_handle = {p.handle: p for p in programs}
    scored: list[Scored] = []
    for target in to_hunt_targets(programs):
        prog = by_handle.get(target.handle)
        if prog is None or not prog.active:
            continue
        base = expected_profit(target, config)
        disc = maturity_discount(prog.audits, prog.age_months, prog.paid_reports)
        scored.append(Scored(program=prog, target=target, base_profit=base, discount=disc,
                             yield_score=round(base * disc, 2),
                             payout=realistic_payout(target)))
    scored.sort(key=lambda s: (-s.yield_score, -s.payout, s.target.repository))
    return scored


def main(argv=None) -> int:
    import sys

    from .registry import load_registry
    path = (argv[0] if argv else (sys.argv[1] if len(sys.argv) > 1 else None))
    programs = load_registry(path)
    if not programs:
        print("no programs in registry — add records to reports/programs.json first")
        return 0
    ranked = score_programs(programs)
    print(f"{'YIELD':>7}  {'PAYOUT$':>8}  {'DISC':>5}  TARGET  (why)")
    for s in ranked[:30]:
        print(f"{s.yield_score:>7.1f}  {s.payout:>8,}  {s.discount:>5.2f}  "
              f"{s.target.repository}   [{s.why()}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
