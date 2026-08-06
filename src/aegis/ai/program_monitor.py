"""Program monitoring — diff the public feeds against the registry and alert on changes.

H1 Disclosed and the Twitter monitors went dark; hunters miss new programs, scope changes,
and pause/resume events. This is the local, ToS-clean version built on the same trusted feeds
as the importer. Each run fetches fresh, diffs against reports/programs.json, and records:

  * new_program    — a program we hadn't seen (hunt it early, before the crowd)
  * scope_changed  — in-scope/out-of-scope assets added or removed (fresh attack surface)
  * reward_changed — reward ceiling moved
  * paused         — a program that was listed is gone from its feed -> marked inactive
  * resumed        — a previously-paused program is back

The pause signal is the money one for automation: a paused program is marked active=False, so
selection/autostart skip it and we stop wasting compute, tokens, and API calls on it — exactly
the failure the monitor exists to prevent. Alerts are appended to reports/program_alerts.json
(newest first) and surfaced in the dashboard. Reads PUBLIC data only; never submits.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .program_sources import _BTD_FILES, BountyTargetsSource, Code4renaSource, _merge

ALERTS_PATH = "reports/program_alerts.json"
_MAX_ALERTS = 500


@dataclass
class Change:
    type: str                     # new_program|scope_changed|reward_changed|paused|resumed
    handle: str
    platform: str = ""
    detail: str = ""
    added: list = field(default_factory=list)      # assets added to scope
    removed: list = field(default_factory=list)    # assets removed from scope
    ts: float = 0.0


def _fetch_fresh(fetch_json=None):
    """Fetch every source, returning ({handle: Program}, {platforms that returned data}).
    Tracking which platforms answered avoids false 'paused' alerts when a feed is briefly down."""
    fresh: dict = {}
    ok: set[str] = set()
    for plat in _BTD_FILES:
        src = BountyTargetsSource(platforms=(plat,))
        if fetch_json is not None:
            src.fetch_json = fetch_json          # type: ignore[attr-defined]
        got = src.fetch()
        if got:
            ok.add(plat)
        for p in got:
            fresh[p.handle] = p
    c4 = Code4renaSource()
    if fetch_json is not None:
        c4.fetch_json = fetch_json               # type: ignore[attr-defined]
    cgot = c4.fetch()
    if cgot:
        ok.add("code4rena")
    for p in cgot:
        fresh[p.handle] = p
    return fresh, ok


def diff(old: dict, fresh: dict, fetched: set[str]) -> list[Change]:
    """Compute change events. `old`/`fresh` are {handle: Program}; `fetched` is the set of
    platforms whose feed answered this run (only those are eligible for pause detection)."""
    now = time.time()
    events: list[Change] = []
    for h, fp in fresh.items():
        op = old.get(h)
        if op is None:
            events.append(Change("new_program", h, fp.platform,
                                 f"{fp.platform} · reward {int(fp.reward_ceiling) or '?'} · "
                                 f"{len(fp.targets)} repo(s)", ts=now))
            continue
        add = sorted(set(fp.targets) - set(op.targets))
        rem = sorted(set(op.targets) - set(fp.targets))
        addo = sorted(set(fp.out_of_scope) - set(op.out_of_scope))
        if add or rem or addo:
            events.append(Change("scope_changed", h, fp.platform,
                                 f"+{len(add)} / -{len(rem)} in-scope, +{len(addo)} excluded",
                                 added=add[:30], removed=rem[:30], ts=now))
        if fp.reward_ceiling and fp.reward_ceiling != op.reward_ceiling:
            events.append(Change("reward_changed", h, fp.platform,
                                 f"{int(op.reward_ceiling)} -> {int(fp.reward_ceiling)}", ts=now))
        if op.active is False:
            events.append(Change("resumed", h, fp.platform, "back in the feed", ts=now))
    for h, op in old.items():
        if h not in fresh and op.platform in fetched and op.active:
            events.append(Change("paused", h, op.platform,
                                 "no longer listed — marked inactive (skipped by selection)",
                                 ts=now))
    return events


def _apply(old: dict, fresh: dict, fetched: set[str]):
    """Return the merged registry: add new, merge changed (preserving operator annotations),
    mark disappeared-in-a-fetched-platform as inactive (paused), leave others untouched."""
    merged = dict(old)
    for h, fp in fresh.items():
        merged[h] = _merge(old[h], fp) if h in old else fp
    for h, op in old.items():
        if h not in fresh and op.platform in fetched and op.active:
            op.active = False
            merged[h] = op
    return merged


def _append_alerts(events: list[Change], store_dir: Path) -> None:
    path = store_dir / "program_alerts.json"
    try:
        prev = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else []
    except (OSError, json.JSONDecodeError):
        prev = []
    rows = [asdict(e) for e in events] + (prev if isinstance(prev, list) else [])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows[:_MAX_ALERTS], indent=2), encoding="utf-8")


def load_alerts(store_dir: str | Path = "reports", limit: int = 100) -> list[dict]:
    path = Path(store_dir) / "program_alerts.json"
    if not path.is_file():
        return []
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return rows[:limit] if isinstance(rows, list) else []


def monitor(store: str | Path | None = None, *, fetch_json=None) -> dict:
    """Run one monitoring pass: fetch fresh, diff against the registry, apply changes, and
    append alerts. Returns a summary. `store` is the programs.json path (default reports/)."""
    from .registry import load_registry, save_registry
    store_path = Path(store) if store else Path("reports/programs.json")
    old = {p.handle: p for p in load_registry(store_path)}
    fresh, fetched = _fetch_fresh(fetch_json)
    if not fetched:
        return {"error": "no feed answered — skipping (avoids false pause alerts)",
                "events": [], "monitored": []}
    events = diff(old, fresh, fetched)
    merged = _apply(old, fresh, fetched)
    save_registry(list(merged.values()), store_path)
    _append_alerts(events, store_path.parent)
    counts: dict[str, int] = {}
    for e in events:
        counts[e.type] = counts.get(e.type, 0) + 1
    return {"events": [asdict(e) for e in events], "counts": counts,
            "monitored": sorted(fetched), "total_programs": len(merged)}


def main(argv=None) -> int:
    summary = monitor()
    if summary.get("error"):
        print("monitor:", summary["error"])
        return 0
    c = summary["counts"]
    print(f"program monitor — feeds: {', '.join(summary['monitored'])}")
    print(f"  new {c.get('new_program',0)} · scope-changed {c.get('scope_changed',0)} · "
          f"reward-changed {c.get('reward_changed',0)} · paused {c.get('paused',0)} · "
          f"resumed {c.get('resumed',0)}")
    for e in summary["events"][:20]:
        print(f"  [{e['type']}] {e['handle']} — {e['detail']}")
    print(f"  alerts -> {ALERTS_PATH}  ({summary['total_programs']} programs in registry)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
