"""Expand the full HackerOne code-bounty inventory into a saturation-scored hunt queue.

Reads reports/hackerone_code_targets.json (the 234 bounty repos) and scores each with a
HEURISTIC saturation (how picked-over the program is), an estimated reward ceiling (from
the severity floor), and a findability estimate (from repo-name signals). These are
ESTIMATES, honestly labelled — not measured hunter density or real bounty tables.

Output: reports/autohunt_targets_full.json, EV-ranked (saturation-penalized). Prints the
NOT-saturated shortlist (saturation <= threshold) that the 24/7 loop should grind.
"""

from __future__ import annotations

import json
from pathlib import Path

SRC = Path("reports/hackerone_code_targets.json")
OUT = Path("reports/autohunt_targets_full.json")

# Fame/saturation heuristic. Elite, heavily-hunted programs -> high saturation (everyone
# is already on them). Unknown/smaller handles default to LOW saturation (less crowded).
_FAMOUS = {
    # mega crowds — landing a bug is near-zero
    "coinbase": 0.95, "gitlab": 0.9, "gitlab-org": 0.9, "cloudflare": 0.9, "shopify": 0.9,
    "discourse": 0.85, "wordpress": 0.85, "automattic": 0.85, "nextcloud": 0.8, "owncloud": 0.75,
    "matomo-org": 0.75, "hackerone": 0.9, "uber": 0.9, "twitter": 0.9, "x": 0.9, "slackhq": 0.8,
    "slack": 0.8, "paragonie": 0.85, "hyperledger": 0.6, "kubernetes": 0.75, "hashicorp": 0.8,
    "plaid": 0.6, "irccloud": 0.5, "mainwp": 0.4, "wordpoints": 0.2, "wordpoints/wordpoints": 0.2,
}
_DEFAULT_SATURATION = 0.35   # an unknown handle is, by assumption, less crowded

# reward ceiling by severity floor (USD, ESTIMATE — real tables vary widely)
_REWARD = {"critical": 5000.0, "high": 2500.0, "medium": 1000.0, "low": 500.0, "none": 0.0}

# findability signals from the repo name (PHP/WP plugins are softer; crypto/security libs harder)
_SOFT = ("wp-", "wordpress", "plugin", "cms", "portal", "web", "app", "api", "admin", "dashboard")
_HARD = ("crypto", "mpc", "sodium", "halite", "cert", "tls", "ssl", "kdf", "cipher", "random",
         "constant_time", "paseto", "nebula", "keystore", "hsm")


def saturation_for(handle: str, repo: str) -> float:
    h = handle.lower()
    if repo.lower() in _FAMOUS:
        return _FAMOUS[repo.lower()]
    if h in _FAMOUS:
        return _FAMOUS[h]
    return _DEFAULT_SATURATION


def findability_for(repo: str) -> float:
    r = repo.lower()
    if any(s in r for s in _HARD):
        return 0.25            # pristine, hard-to-find, elite-audited surface
    if any(s in r for s in _SOFT):
        return 0.65            # softer web/plugin surface
    return 0.45


def ev(reward: float, findability: float, saturation: float) -> float:
    crowd = 1.0 - min(1.0, max(0.0, saturation))
    return round(findability * crowd * crowd * 0.30 * 0.60 * reward, 2)


def main() -> int:
    d = json.loads(SRC.read_text(encoding="utf-8"))
    rows = []
    for g in d["code_bounty"]:
        handle = g["handle"]
        for repo, sev in g["repos"]:
            if "*" in repo or repo.startswith("github.com") or "/" not in repo:
                continue           # not a clonable owner/repo
            reward = _REWARD.get(sev, 1000.0)
            sat = saturation_for(handle, repo)
            find = findability_for(repo)
            rows.append({
                "repository": repo, "handle": handle, "reward_ceiling": reward,
                "findability": find, "saturation": sat, "subpath": "", "kind": "repo",
                "severity_floor": sev, "ev_estimate": ev(reward, find, sat),
            })
    rows.sort(key=lambda r: -r["ev_estimate"])
    OUT.write_text(json.dumps(rows, indent=1), encoding="utf-8")
    fresh = [r for r in rows if r["saturation"] <= 0.5]
    print(f"built {len(rows)} code targets -> {OUT}")
    print(f"NOT-saturated (<=0.5): {len(fresh)}  |  crowded (>0.5): {len(rows)-len(fresh)}")
    print("\nTop 20 least-crowded, highest-EV:")
    for r in fresh[:20]:
        print(f"  ${r['ev_estimate']:>7.0f}  crowd={int(r['saturation']*100):>3}%  "
              f"find={r['findability']}  {r['severity_floor']:8}  {r['repository']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
