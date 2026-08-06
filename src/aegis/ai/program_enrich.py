"""Program enrichment — give the selection scorer real money + maturity signals.

Selection was blind: every program scored with maturity_discount 1.0 (no audits/age/history)
and HackerOne ships no reward figure, so EV collapsed to 0 for the biggest feed. This fills
those gaps from data we already have or can fetch cheaply — real signals, clearly labeled:

  1. reward from disclosed payouts — a program's max REAL disclosed bounty (Bugcrowd
     crowdstream) becomes its reward_ceiling. Actual money, not a guess.
  2. crowding — how many disclosed reports a program has -> paid_reports (the "picked-over"
     maturity signal that drives the selection discount).
  3. repo age — GitHub created_at -> age_months (real maturity), bounded + token-gated so it
     never blows the API rate limit.
  4. platform reward priors — for programs still at $0 (mostly HackerOne, no public amount),
     a per-platform PRIOR so EV isn't zero. Marked '[reward=prior]' in notes so it's never
     mistaken for a real figure.

Deterministic joins (1-3) need no network beyond the optional GitHub step. Read-only; mutates
the registry in place and re-saves.
"""

from __future__ import annotations

import os
import re
from collections import defaultdict

# Labeled priors: a rough typical ceiling per platform, used ONLY when no real amount exists.
# Not a claim about any specific program — a prior so the ranker isn't blind. Tune freely.
PLATFORM_REWARD_PRIOR = {
    "immunefi": 50000, "code4rena": 25000, "hackerone": 2500,
    "bugcrowd": 2000, "intigriti": 2000, "yeswehack": 1500, "federacy": 500,
}


def _code_from_url(url: str) -> str:
    return (url or "").rstrip("/").split("/")[-1].lower()


def _handle_for_disclosed(row: dict) -> str:
    """Registry handle a Bugcrowd disclosed row would map to (bugcrowd-<engagement_code>)."""
    if row.get("platform") == "bugcrowd":
        return "bugcrowd-" + _code_from_url(row.get("program_url", ""))
    return ""


def enrich_from_disclosed(programs: list, disclosed: list[dict]) -> int:
    """Set reward_ceiling (max real disclosed amount) and paid_reports (count) per program
    from the disclosed feed. Returns how many programs were touched. Real payout data."""
    by_handle_amounts: dict[str, list[float]] = defaultdict(list)
    by_handle_count: dict[str, int] = defaultdict(int)
    for r in disclosed:
        h = _handle_for_disclosed(r)
        if not h:
            continue
        by_handle_count[h] += 1
        if not r.get("amount_estimated") and r.get("amount"):
            by_handle_amounts[h].append(float(r["amount"]))
    touched = 0
    for p in programs:
        amts = by_handle_amounts.get(p.handle)
        cnt = by_handle_count.get(p.handle, 0)
        changed = False
        if amts:
            top = max(amts)
            if top > p.reward_ceiling:
                p.reward_ceiling = top
                changed = True
        if cnt and cnt > p.paid_reports:
            p.paid_reports = cnt
            changed = True
        touched += 1 if changed else 0
    return touched


def apply_reward_priors(programs: list) -> int:
    """For programs still at reward 0, apply a labeled per-platform prior so EV isn't zero."""
    n = 0
    for p in programs:
        if not p.reward_ceiling:
            prior = PLATFORM_REWARD_PRIOR.get(p.platform, 0)
            if prior:
                p.reward_ceiling = prior
                if "[reward=prior]" not in (p.notes or ""):
                    p.notes = (p.notes + " [reward=prior]").strip()
                n += 1
    return n


def _stars_to_saturation(stars: int) -> float:
    """Fame proxy: more stars = more eyes = more picked-over. log-scaled, capped at 0.9.
    ~50 stars -> 0.34, ~500 -> 0.54, ~5k -> 0.74, ~50k -> 0.90."""
    import math
    if stars <= 0:
        return 0.0
    return min(0.9, round(math.log10(stars + 1) / 5.0, 3))


def _github_repo_meta(repo: str, fetch_json, token: str = ""):
    """Return (age_months|None, stars). One call, used for both age and the saturation proxy."""
    import datetime
    headers = {"User-Agent": "aegis-enrich"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        d = fetch_json(f"https://api.github.com/repos/{repo}", headers) or {}
    except Exception:
        return None, 0
    stars = int(d.get("stargazers_count") or 0)
    created = d.get("created_at")
    age = None
    if created:
        try:
            dt = datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
            age = max(0, (datetime.datetime.now(datetime.timezone.utc) - dt).days // 30)
        except Exception:
            age = None
    return age, stars


def enrich_age_from_github(programs: list, *, fetch_json=None, cap: int | None = None) -> int:
    """Fill age_months from a program's first GitHub repo target (real maturity). Bounded by
    `cap` (GitHub unauth allows 60/hr; a GITHUB_TOKEN raises it to 5000/hr). With a token the
    default cap is 1000 (full backfill); unauth it stays conservative at 40. Fills missing only."""
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if cap is None:
        cap = int(os.environ.get("AEGIS_GITHUB_AGE_CAP", "1000" if token else "40") or 40)
    if fetch_json is None:
        import httpx

        def fetch_json(url, headers):   # noqa
            r = httpx.get(url, timeout=20, headers=headers)
            r.raise_for_status()
            return r.json()
    done = 0
    for p in programs:
        if done >= cap:
            break
        if not p.targets or (p.age_months and p.saturation):
            continue        # need a fetch only if age OR saturation is still missing
        repo = next((t for t in p.targets if re.match(r"^[\w.-]+/[\w.-]+$", t)), "")
        if not repo:
            continue
        m, stars = _github_repo_meta(repo, fetch_json, token)
        if m is None and not stars:
            continue
        if m is not None:
            p.age_months = m
        # saturation = fame (stars) OR crowding (disclosed reports), whichever is higher
        sat = max(_stars_to_saturation(stars), min(0.9, p.paid_reports / 40.0))
        if sat > p.saturation:
            p.saturation = sat
        done += 1
    return done


def enrich(store=None, *, use_github: bool = False, fetch_json=None) -> dict:
    """Run the enrichments over the registry and persist. `use_github` is opt-in (rate limits).
    Returns a summary."""
    from .disclosed_reports import load as load_disclosed
    from .registry import load_registry, save_registry
    programs = load_registry(store)
    disclosed = load_disclosed(os.environ.get("AEGIS_REPORT_DIR", "reports"), limit=500)
    from_disc = enrich_from_disclosed(programs, disclosed)
    aged = enrich_age_from_github(programs, fetch_json=fetch_json) if use_github else 0
    priors = apply_reward_priors(programs)
    save_registry(programs, store)
    with_reward = sum(1 for p in programs if p.reward_ceiling)
    with_age = sum(1 for p in programs if p.age_months)
    return {"programs": len(programs), "reward_from_disclosed": from_disc,
            "aged_from_github": aged, "reward_priors_applied": priors,
            "with_reward": with_reward, "with_age": with_age,
            "disclosed_available": len(disclosed)}


def main(argv=None) -> int:
    import sys
    use_gh = "--github" in (argv if argv is not None else sys.argv[1:])
    s = enrich(use_github=use_gh)
    print("program enrichment:")
    print(f"  reward from disclosed payouts: {s['reward_from_disclosed']} programs")
    print(f"  reward priors applied (labeled): {s['reward_priors_applied']}")
    print(f"  ages from GitHub: {s['aged_from_github']}" + ("" if use_gh else " (pass --github to enable)"))
    print(f"  -> {s['with_reward']}/{s['programs']} now have a reward, {s['with_age']} have an age")
    print("  next: python -m aegis.ai.selection")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
