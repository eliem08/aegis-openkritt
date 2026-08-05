"""Audit every accessible HackerOne program for web-lane eligibility.

For each program: pull policy + structured scopes (read-only Hacker API), then classify
whether ACTIVE automated scanning is permitted, and list the in-scope WEB (URL) assets.

Three-way permission verdict — because for active scanning "didn't say no" is NOT "said
yes":
  PERMITTED   policy EXPLICITLY allows automated tools / scanners
  SILENT      policy neither permits nor forbids automation (default; needs human OK)
  PROHIBITED  policy forbids automated tooling  -> never scan

Output: reports/web_scope_audit.json. This is passive discovery only. It produces a
vetted shortlist for a human to approve specific hosts — it launches nothing.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()
from aegis.ingest.hackerone import HackerOneClient  # noqa: E402

# Explicit-permission signals (the parser in ingest/program.py only flags prohibitions).
_ALLOW = [
    r"automated (scanning|testing|tools?) (is|are) (allowed|permitted|ok|fine|welcome)",
    r"you (may|can) (use|run) (automated )?(scanners?|automated tools?)",
    r"(scanners?|scanning) (is|are) (allowed|permitted)",
    r"automation is (allowed|permitted|welcome)",
    r"feel free to (use|run) (automated )?(scanners?|tools?)",
]


def explicit_allow(policy: str) -> bool:
    t = (policy or "").lower()
    return any(re.search(p, t) for p in _ALLOW)


def web_assets(rules) -> list[str]:
    """In-scope, submission-eligible URL/web assets only (skip code repos, mobile, etc.)."""
    out = []
    for s in getattr(rules, "in_scope", []) or []:
        atype = (getattr(s, "asset_type", "") or "").upper()
        ident = getattr(s, "identifier", "") or ""
        if atype in ("URL", "WILDCARD", "DOMAIN", "IP_ADDRESS", "CIDR") and getattr(s, "eligible_for_submission", False):
            out.append(ident)
    return out


def main() -> int:
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 0   # 0 = all accessible programs
    client = HackerOneClient.from_env()
    handles = [p.get("attributes", {}).get("handle") or p.get("id")
               for p in client.list_programs(max_pages=25)]
    handles = [h for h in handles if h]
    if limit:
        handles = handles[:limit]
    print(f"auditing {len(handles)} accessible programs ...", flush=True)

    rows, permitted, silent, prohibited, no_web = [], 0, 0, 0, 0
    for i, handle in enumerate(handles, 1):
        try:
            r = client.fetch_program_rules(handle)
            policy = getattr(r, "policy_text", "") or getattr(r, "policy", "") or ""
            assets = web_assets(r)
            if not r.automation_allowed:
                verdict = "PROHIBITED"; prohibited += 1
            elif explicit_allow(policy):
                verdict = "PERMITTED"; permitted += 1
            else:
                verdict = "SILENT"; silent += 1
            if not assets:
                no_web += 1
            rows.append({
                "handle": handle, "verdict": verdict, "web_assets": assets[:50],
                "web_asset_count": len(assets), "ai_allowed": r.ai_allowed,
                "rate_limit_rps": r.rate_limit_rps,
            })
        except Exception as exc:
            rows.append({"handle": handle, "verdict": "ERROR", "error": type(exc).__name__})
        if i % 20 == 0:
            print(f"  {i}/{len(handles)} …", flush=True)

    # the actionable set: EXPLICITLY permitted AND has in-scope web assets
    scannable = [r for r in rows if r.get("verdict") == "PERMITTED" and r.get("web_asset_count")]
    out = {"summary": {"audited": len(rows), "permitted": permitted, "silent": silent,
                       "prohibited": prohibited, "no_web_assets": no_web,
                       "scannable_now": len(scannable)},
           "scannable_now": scannable, "all": rows}
    Path("reports/web_scope_audit.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(json.dumps(out["summary"], indent=1))
    print(f"\nEXPLICITLY scanning-permitted with web scope: {len(scannable)}")
    for r in scannable[:25]:
        print(f"  {r['handle']:24} {r['web_asset_count']} web asset(s)  rate={r['rate_limit_rps']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
