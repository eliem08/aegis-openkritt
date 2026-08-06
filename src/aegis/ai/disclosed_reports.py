"""Disclosed-report monitoring — newly disclosed public reports, filtered + summarised.

The one piece the program-feed monitor doesn't cover: newly *disclosed* reports, so you can
learn from what's landing and spot patterns. Built on public data only:

  * Bugcrowd crowdstream (https://bugcrowd.com/crowdstream.json) — a public JSON feed of
    disclosed submissions. Real, clean, ToS-safe. Implemented.
  * HackerOne hacktivity — their public disclosures moved behind an undocumented GraphQL
    schema that changes without notice; reverse-engineering it is brittle and ToS-gray, so
    the H1 adapter degrades to empty rather than ship something fragile. Plugs in if a
    working query is supplied.

Filtering matches what a hunter actually wants: drop N/A / Informational / spam substates and
the curl-program AI-slop flood. When the bounty amount is hidden, estimate a band from the
priority. An optional one-line summary (deterministic, or LLM if a client is passed) says why
a report might be worth reading. Alerts stored in reports/disclosed_reports.json. Read-only;
never submits.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

_CROWDSTREAM = "https://bugcrowd.com/crowdstream.json"
STORE = "reports/disclosed_reports.json"
_MAX = 500

# Bugcrowd priority (P1..P5) -> severity + an estimated $ band when the real amount is hidden.
_PRI = {1: ("critical", 5000), 2: ("high", 2000), 3: ("medium", 750),
        4: ("low", 250), 5: ("info", 0)}
# substates that are noise — not worth surfacing.
_NOISE_SUBSTATE = {"not_applicable", "informational", "informative", "spam", "out_of_scope"}


@dataclass
class Disclosed:
    id: str
    platform: str
    program: str
    program_url: str
    subject: str            # target / short description
    severity: str
    amount: float           # disclosed amount, or the ESTIMATE when hidden
    amount_estimated: bool
    substate: str
    state_text: str
    disclosed_at: str
    summary: str = ""
    ts: float = 0.0


def _money(x) -> float:
    """Parse a crowdstream amount that may be '$1,500', 1500, '', or None -> float."""
    if isinstance(x, (int, float)):
        return float(x)
    if isinstance(x, str):
        cleaned = x.replace("$", "").replace(",", "").strip()
        try:
            return float(cleaned)
        except ValueError:
            return 0.0
    return 0.0


def _default_fetch_json(url: str, timeout: float = 25.0):
    import httpx
    r = httpx.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0 aegis-research"},
                  follow_redirects=True)
    r.raise_for_status()
    return r.json()


def _is_vdp(entry: dict) -> bool:
    name = (entry.get("engagement_name") or "").lower()
    code = (entry.get("engagement_code") or "").lower()
    return "vulnerability disclosure" in name or code.endswith("-vdp") or "vdp" in code.split("-")


def _is_noise(entry: dict) -> bool:
    sub = (entry.get("substate") or "").lower()
    if sub in _NOISE_SUBSTATE:
        return True
    # curl's AI-slop flood: the curl program is swamped with invalid AI-generated reports;
    # keep only ones that were actually resolved/rewarded.
    code = (entry.get("engagement_code") or "").lower()
    if code == "curl" and sub not in ("resolved",) and not entry.get("crowdstream_amount_visible"):
        return True
    return False


def _map_bugcrowd(entry: dict) -> Disclosed | None:
    if not isinstance(entry, dict) or not entry.get("id"):
        return None
    pr = entry.get("priority")
    sev, est = _PRI.get(int(pr) if isinstance(pr, int) or (isinstance(pr, str) and pr.isdigit())
                        else 0, ("unknown", 0))
    visible = bool(entry.get("crowdstream_amount_visible"))
    real = _money(entry.get("amount"))
    amt = real if (visible and real) else float(est)
    amount_estimated = not (visible and real)
    path = entry.get("engagement_path") or ""
    return Disclosed(
        id=f"bc:{entry.get('id')}", platform="bugcrowd",
        program=entry.get("engagement_name") or "", program_url=("https://bugcrowd.com" + path) if path else "",
        subject=str(entry.get("target") or entry.get("submission_state_text") or "")[:200],
        severity=sev, amount=amt, amount_estimated=amount_estimated,
        substate=str(entry.get("substate") or ""),
        state_text=str(entry.get("submission_state_text") or ""),
        disclosed_at=str(entry.get("disclosed") or entry.get("closed_at") or ""),
        ts=time.time())


def fetch_bugcrowd(fetch_json=None, *, drop_vdp: bool = True) -> list[Disclosed]:
    fj = fetch_json or _default_fetch_json
    try:
        data = fj(_CROWDSTREAM)
    except Exception:
        return []
    out: list[Disclosed] = []
    for entry in (data.get("results") if isinstance(data, dict) else []) or []:
        if drop_vdp and _is_vdp(entry):
            continue
        if _is_noise(entry):
            continue
        d = _map_bugcrowd(entry)
        if d:
            d.summary = _basic_summary(d)
            out.append(d)
    return out


def fetch_hackerone(fetch_json=None) -> list[Disclosed]:
    """HackerOne disclosed reports. Their public hacktivity is an undocumented GraphQL schema
    that changes without notice; until a stable query is available this degrades to empty
    rather than ship a brittle scraper. Returns []."""
    return []


def _basic_summary(d: Disclosed) -> str:
    amt = (f"~${int(d.amount):,} (est)" if d.amount_estimated and d.amount
           else (f"${int(d.amount):,}" if d.amount else "no bounty shown"))
    return f"{d.severity.upper()} · {d.program} · {amt} · {d.state_text or d.substate}"


def summarize_with_llm(reports: list[Disclosed], client, *, limit: int = 15) -> None:
    """Optionally replace the basic summary with a one-line LLM 'why worth reading' for the
    newest `limit` reports. Bounded to control cost; degrades to the basic summary on error."""
    for d in reports[:limit]:
        try:
            raw = client.complete_json([
                {"role": "system", "content": "You summarise a disclosed bug-bounty report in "
                 "ONE sentence: what class of bug and why a hunter might read it. Return "
                 '{"summary":"..."}. Be concrete, no fluff.'},
                {"role": "user", "content": json.dumps(
                    {"program": d.program, "subject": d.subject, "severity": d.severity,
                     "amount": d.amount, "state": d.state_text})},
            ])
            s = str(raw.get("summary", "")).strip()
            if s:
                d.summary = s[:280]
        except Exception:
            continue


def load(store_dir: str | Path = "reports", limit: int = 100) -> list[dict]:
    path = Path(store_dir) / "disclosed_reports.json"
    if not path.is_file():
        return []
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return rows[:limit] if isinstance(rows, list) else []


def collect(store: str | Path | None = None, *, fetch_json=None, client=None) -> dict:
    """Fetch + filter + estimate + (optionally) LLM-summarise disclosed reports, merge into
    the store newest-first (dedup by id), and return a summary."""
    path = Path(store) if store else Path(STORE)
    fresh = fetch_bugcrowd(fetch_json) + fetch_hackerone(fetch_json)
    try:
        prev = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else []
    except (OSError, json.JSONDecodeError):
        prev = []
    seen = {r.get("id") for r in prev if isinstance(r, dict)}
    new = [d for d in fresh if d.id not in seen]
    if client is not None and new:
        summarize_with_llm(new, client)
    rows = [asdict(d) for d in new] + (prev if isinstance(prev, list) else [])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows[:_MAX], indent=2), encoding="utf-8")
    return {"fetched": len(fresh), "new": len(new), "total": len(rows[:_MAX]),
            "platforms": sorted({d.platform for d in fresh})}


def main(argv=None) -> int:
    s = collect()
    print(f"disclosed reports — platforms: {', '.join(s['platforms']) or '(none reachable)'}")
    print(f"  fetched {s['fetched']} · new {s['new']} · stored {s['total']}")
    for r in load(limit=15):
        est = " (est)" if r.get("amount_estimated") else ""
        print(f"  [{r.get('severity','?'):8}] ${int(r.get('amount',0)):>6,}{est}  {r.get('program','')[:40]}  {r.get('subject','')[:50]}")
    print(f"  -> {STORE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
