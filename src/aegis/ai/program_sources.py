"""Program importers — populate the registry from trusted, read-only program feeds.

Every successful fetch stamps the resulting :class:`Program` with source/scope retrieval time.
That timestamp is part of the authorization boundary: an old local registry is not treated as
fresh permission indefinitely. GitHub exclusions are normalized to ``owner/repo`` so they can
actually match normalized targets.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone

from .registry import Program

_BTD = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data"
_BTD_FILES = {
    "hackerone": "hackerone_data.json",
    "bugcrowd": "bugcrowd_data.json",
    "intigriti": "intigriti_data.json",
    "yeswehack": "yeswehack_data.json",
    "federacy": "federacy_data.json",
}
_C4_ORG = "https://api.github.com/orgs/code-423n4/repos?per_page=100&sort=created&direction=desc"
_C4_NOISE = re.compile(
    r"(-findings|-validation|-submissions|submissions-tmp|-tmp-|-tmp$|template|dashboard|"
    r"website|^docs|\.github|media|brand|backstage|org-|-org$)", re.IGNORECASE)

_GITHUB_RE = re.compile(r"github\.com[:/]+([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", re.IGNORECASE)
_ASSET_KEYS = ("asset_identifier", "target", "endpoint", "url", "asset", "identifier", "name")


def _utcnow_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _default_fetch_json(url: str, timeout: float = 30.0, headers: dict | None = None):
    """Fetch and JSON-decode a URL. Isolated so tests inject a fake fetcher instead."""
    import httpx

    hdrs = {"User-Agent": "aegis-registry-import", "Accept": "application/json"}
    hdrs.update(headers or {})
    resp = httpx.get(url, timeout=timeout, headers=hdrs)
    resp.raise_for_status()
    return resp.json()


def _asset_str(item) -> str:
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        for k in _ASSET_KEYS:
            v = item.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return ""


def repo_from_asset(asset: str) -> str:
    """``https://github.com/owner/repo(.git)?/...`` -> ``owner/repo``."""
    m = _GITHUB_RE.search(asset or "")
    if not m:
        return ""
    return m.group(1).removesuffix(".git").rstrip("/")


def _normalized_scope_asset(asset: str) -> str:
    return repo_from_asset(asset) or str(asset or "").strip()


def _slug_from_url(url: str) -> str:
    return (url or "").rstrip("/").rsplit("/", 1)[-1] or ""


def _scope_text(in_scope: list[str], out_scope: list[str]) -> str:
    parts = []
    if in_scope:
        parts.append("In scope: " + ", ".join(in_scope[:60]))
    if out_scope:
        parts.append("Out of scope: " + ", ".join(out_scope[:60]))
    return "\n".join(parts)[:8000]


def _num(x) -> float:
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


def _map_generic(platform: str, entry: dict, *, kind: str = "repo",
                 reward_keys=("max_payout", "max_bounty", "maxBounty")) -> Program | None:
    if not isinstance(entry, dict):
        return None
    url = str(entry.get("url") or "")
    name = str(entry.get("name") or _slug_from_url(url) or "").strip()
    if not name and not url:
        return None
    tgt = entry.get("targets") if isinstance(entry.get("targets"), dict) else {}
    in_items = tgt.get("in_scope") or entry.get("assets") or []
    out_items = tgt.get("out_of_scope") or []
    in_scope = [s for s in (_asset_str(i) for i in in_items) if s]
    out_scope_raw = [s for s in (_asset_str(i) for i in out_items) if s]
    out_scope = [_normalized_scope_asset(s) for s in out_scope_raw]
    repos: list[str] = []
    for s in in_scope:
        r = repo_from_asset(s)
        if r and r not in repos:
            repos.append(r)
    reward = 0.0
    for k in reward_keys:
        reward = reward or _num(entry.get(k))
    slug = str(entry.get("handle") or _slug_from_url(url) or name).strip()
    handle = slug if platform == "hackerone" else f"{platform}-{slug}"
    active = bool(entry.get("offers_bounties", True)) and not entry.get("disabled", False)
    fetched_at = _utcnow_iso()
    return Program(
        handle=handle, platform=platform, url=url,
        targets=repos,
        bounty_eligible_targets=list(repos) if active else [],
        kind="contract" if platform == "immunefi" else kind,
        out_of_scope=out_scope[:60], reward_ceiling=reward,
        scope_text=_scope_text(in_scope, out_scope_raw),
        source_retrieved_at=fetched_at, scope_retrieved_at=fetched_at,
        active=active,
    )


@dataclass
class BountyTargetsSource:
    """HackerOne/Bugcrowd/Intigriti/YesWeHack/Federacy via bounty-targets-data."""
    fetch_json = staticmethod(_default_fetch_json)
    platforms: tuple = tuple(_BTD_FILES)
    source_code_only: bool = False

    def fetch(self) -> list[Program]:
        out: list[Program] = []
        for platform in self.platforms:
            fname = _BTD_FILES.get(platform)
            if not fname:
                continue
            try:
                data = self.fetch_json(f"{_BTD}/{fname}")
            except Exception:
                continue
            for entry in data if isinstance(data, list) else []:
                prog = _map_generic(platform, entry)
                if prog is None:
                    continue
                if self.source_code_only and not prog.targets:
                    continue
                out.append(prog)
        return out


@dataclass
class Code4renaSource:
    """Code4rena contest repositories from the public code-423n4 GitHub organization."""
    fetch_json = staticmethod(_default_fetch_json)
    max_repos: int = 100

    def fetch(self) -> list[Program]:
        try:
            data = self.fetch_json(_C4_ORG)
        except Exception:
            return []
        out: list[Program] = []
        fetched_at = _utcnow_iso()
        for repo in (data if isinstance(data, list) else [])[: self.max_repos]:
            if not isinstance(repo, dict) or repo.get("archived") or repo.get("fork"):
                continue
            full = str(repo.get("full_name") or "")
            if not full:
                continue
            name = str(repo.get("name") or "")
            if _C4_NOISE.search(name):
                continue
            out.append(Program(
                handle=f"code4rena-{name}", platform="code4rena",
                url=str(repo.get("html_url") or ""), targets=[full],
                bounty_eligible_targets=[full], kind="contract",
                reward_ceiling=0.0, findability=0.6,
                scope_text=f"Code4rena contest repo {full}. "
                           f"{repo.get('description') or ''!s}"[:8000],
                source_retrieved_at=fetched_at, scope_retrieved_at=fetched_at,
                notes="reward pool not in feed — fill reward_ceiling from the c4 contest page",
                active=not bool(repo.get("archived")),
            ))
        return out


_SOURCES = {"bountytargets": BountyTargetsSource, "code4rena": Code4renaSource}


def _merge(existing: Program, fresh: Program) -> Program:
    """Refresh source-derived fields while preserving operator annotations."""
    fresh.audits = existing.audits or fresh.audits
    fresh.age_months = existing.age_months or fresh.age_months
    fresh.paid_reports = existing.paid_reports or fresh.paid_reports
    fresh.notes = existing.notes or fresh.notes
    if not fresh.reward_ceiling and existing.reward_ceiling:
        fresh.reward_ceiling = existing.reward_ceiling
    return fresh


def import_programs(sources: list[str] | None = None, *, store=None,
                    source_code_only: bool = False, fetch_json=None,
                    include_connectors: bool = True) -> dict:
    """Fetch sources, merge into the canonical registry, and return an audit summary."""
    from .registry import load_registry, save_registry

    names = sources or list(_SOURCES)
    fetched: list[Program] = []
    per_source: dict[str, int] = {}
    for name in names:
        cls = _SOURCES.get(name)
        if cls is None:
            continue
        src = cls()
        if fetch_json is not None:
            src.fetch_json = fetch_json           # type: ignore[attr-defined]
        if name == "bountytargets":
            src.source_code_only = source_code_only
        got = src.fetch()
        per_source[name] = len(got)
        fetched.extend(got)

    connector_status: list = []
    if include_connectors and sources is None:
        from .program_connectors import fetch_connectors

        cres = fetch_connectors()
        fetched.extend(cres.programs)
        for st in cres.statuses:
            per_source[st.name] = st.fetched
        connector_status = [st.__dict__ for st in cres.statuses]

    existing = {p.handle: p for p in load_registry(store)}
    pruned = [h for h, p in existing.items()
              if p.platform == "code4rena" and _C4_NOISE.search(h)]
    for h in pruned:
        del existing[h]
    added = updated = 0
    for prog in fetched:
        if prog.handle in existing:
            existing[prog.handle] = _merge(existing[prog.handle], prog)
            updated += 1
        else:
            existing[prog.handle] = prog
            added += 1
    merged = list(existing.values())
    save_registry(merged, store)
    with_repo = sum(1 for p in merged if p.targets)
    return {"per_source": per_source, "fetched": len(fetched), "added": added,
            "updated": updated, "total_in_registry": len(merged),
            "with_source_repo": with_repo, "connectors": connector_status}


def main(argv=None) -> int:
    import sys

    from ..env import load_dotenv

    load_dotenv()
    args = list(argv if argv is not None else sys.argv[1:])
    if "--status" in args:
        from .program_connectors import connector_status

        print("bounty source connectors:")
        for name in _SOURCES:
            print(f"  {name:16} available=True  (public feed, no auth)")
        for st in connector_status():
            tag = "available=True " if st.available else "available=False"
            print(f"  {st.name:16} {tag} {st.blocked_reason}")
        return 0
    src_arg = [a for a in args if not a.startswith("-")]
    sources = None if (not src_arg or src_arg == ["all"]) else src_arg
    summary = import_programs(sources, source_code_only="--source-code-only" in args)
    print("imported program feeds -> reports/programs.json")
    for k, v in summary["per_source"].items():
        print(f"  {k:16} {v} programs")
    for st in summary.get("connectors", []):
        if not st.get("available"):
            print(f"  {st['name']:16} BLOCKED - {st['blocked_reason']}")
        elif st.get("error"):
            print(f"  {st['name']:16} ERROR - {st['error']}")
    print(f"  added {summary['added']}, updated {summary['updated']}, "
          f"total {summary['total_in_registry']} ({summary['with_source_repo']} with a source repo)")
    print("next: `python -m aegis.ai.selection` to rank them by yield")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
