"""Authenticated, first-party bounty-platform connectors.

Connectors are GET-only, never invent credentials, and normalize into the single canonical
:class:`aegis.ai.registry.Program` model. HackerOne is live-validated; the other authenticated
mappers remain fixture-tested until credentials are available.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

from .program_sources import _asset_str, _default_fetch_json, _num, _scope_text, repo_from_asset
from .registry import Program


@runtime_checkable
class ProgramSource(Protocol):
    name: str

    def available(self) -> bool: ...
    def blocked_reason(self) -> str: ...
    def fetch(self) -> list[Program]: ...


@dataclass
class SourceStatus:
    name: str
    available: bool
    blocked_reason: str = ""
    fetched: int = 0
    error: str = ""


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _first_env(*names: str) -> str:
    for n in names:
        v = os.environ.get(n, "").strip()
        if v:
            return v
    return ""


def _normalize_asset(value: str) -> str:
    return repo_from_asset(value) or str(value or "").strip()


def _repos_and_scope(in_items, out_items) -> tuple[list[str], list[str], list[str]]:
    """Turn raw scope items into repositories, raw in-scope strings, normalized exclusions."""
    in_scope = [s for s in (_asset_str(i) for i in (in_items or [])) if s]
    out_raw = [s for s in (_asset_str(i) for i in (out_items or [])) if s]
    repos: list[str] = []
    for s in in_scope:
        r = repo_from_asset(s)
        if r and r not in repos:
            repos.append(r)
    out_scope = [_normalize_asset(s) for s in out_raw]
    return repos, in_scope, out_scope


@dataclass
class HackerOneConnector:
    name: str = "hackerone-api"
    fetch_json = staticmethod(_default_fetch_json)
    max_pages: int = 20
    max_scope_pages: int = 20

    def _auth(self) -> tuple[str, str] | None:
        u = _first_env("HACKERONE_API_USERNAME", "H1_API_USERNAME")
        t = _first_env("HACKERONE_API_TOKEN", "H1_API_TOKEN")
        return (u, t) if (u and t) else None

    def available(self) -> bool:
        return self._auth() is not None

    def blocked_reason(self) -> str:
        return "" if self.available() else (
            "set HACKERONE_API_USERNAME + HACKERONE_API_TOKEN "
            "(HackerOne API HTTP Basic auth)")

    def _headers(self) -> dict:
        u, t = self._auth()  # type: ignore[misc]
        tok = base64.b64encode(f"{u}:{t}".encode()).decode()
        return {"Authorization": f"Basic {tok}", "Accept": "application/json"}

    def _structured_scopes(self, handle: str, headers: dict) -> dict:
        """Fetch every structured-scope page, not only the first 100 assets."""
        max_pages = int(_first_env("AEGIS_H1_SCOPE_MAX_PAGES") or self.max_scope_pages)
        url = ("https://api.hackerone.com/v1/hackers/programs/"
               f"{handle}/structured_scopes?page[size]=100")
        rows: list[dict] = []
        for _ in range(max_pages):
            data = self.fetch_json(url, headers=headers)
            if isinstance(data, dict):
                rows.extend(x for x in (data.get("data") or []) if isinstance(x, dict))
                nxt = (data.get("links") or {}).get("next") or ""
            else:
                nxt = ""
            if not nxt:
                break
            url = str(nxt)
        return {"data": rows}

    def fetch(self) -> list[Program]:
        if not self.available():
            return []
        headers = self._headers()
        max_pages = int(_first_env("AEGIS_H1_MAX_PAGES") or self.max_pages)
        url = "https://api.hackerone.com/v1/hackers/programs?page[size]=100"
        out: list[Program] = []
        want_scopes = _first_env("AEGIS_H1_FETCH_SCOPES").lower() in ("1", "true", "yes")
        for _ in range(max_pages):
            try:
                data = self.fetch_json(url, headers=headers)
            except Exception:
                break
            for entry in (data.get("data") or []) if isinstance(data, dict) else []:
                prog = self.map_program(entry)
                if prog is None:
                    continue
                if want_scopes and prog.active:
                    try:
                        self.apply_scopes(prog, self._structured_scopes(prog.handle, headers))
                    except Exception:
                        # No scope freshness is stamped on failure, so target authorization fails
                        # closed rather than treating a partial/old scope as current permission.
                        pass
                out.append(prog)
            nxt = ((data.get("links") or {}).get("next")) if isinstance(data, dict) else ""
            if not nxt:
                break
            url = str(nxt)
        return out

    @staticmethod
    def map_program(entry: dict) -> Program | None:
        if not isinstance(entry, dict):
            return None
        a = entry.get("attributes") or {}
        handle = str(a.get("handle") or "").strip()
        if not handle:
            return None
        state = str(a.get("submission_state") or "open").lower()
        return Program(
            handle=handle,
            platform="hackerone",
            url=f"https://hackerone.com/{handle}",
            reward_ceiling=_num(a.get("max_bounty") or a.get("base_bounty")),
            active=(state == "open") and bool(a.get("offers_bounties", True)),
            scope_text=str(a.get("policy") or a.get("name") or handle)[:8000],
            source_retrieved_at=_now_iso(),
            notes="HackerOne API; structured scopes required for repository authorization",
        )

    @staticmethod
    def apply_scopes(prog: Program, scopes_data: dict) -> Program:
        """Preserve submission eligibility and monetary-bounty eligibility separately."""
        rows = (scopes_data.get("data") or []) if isinstance(scopes_data, dict) else []
        submission_items: list[str] = []
        bounty_items: list[str] = []
        out_items: list[str] = []
        bounty_known = False
        for r in rows:
            at = (r.get("attributes") or {}) if isinstance(r, dict) else {}
            ident = str(at.get("asset_identifier") or "").strip()
            if not ident:
                continue
            eligible_submission = at.get("eligible_for_submission") is True
            if eligible_submission:
                submission_items.append(ident)
            else:
                out_items.append(ident)
            if "eligible_for_bounty" in at:
                bounty_known = True
                if eligible_submission and at.get("eligible_for_bounty") is True:
                    bounty_items.append(ident)

        repos, in_scope, out_scope = _repos_and_scope(submission_items, out_items)
        bounty_repos, _, _ = _repos_and_scope(bounty_items, [])
        prog.targets = repos
        prog.out_of_scope = out_scope[:60]
        prog.bounty_eligibility_known = bounty_known
        prog.bounty_eligible_targets = bounty_repos if bounty_known else []
        prog.scope_text = (_scope_text(in_scope, out_scope) or prog.scope_text)[:8000]
        prog.scope_retrieved_at = _now_iso()
        return prog


@dataclass
class BugcrowdConnector:
    name: str = "bugcrowd-api"
    fetch_json = staticmethod(_default_fetch_json)
    max_pages: int = 10

    def _token(self) -> str:
        return _first_env("BUGCROWD_API_TOKEN", "BUGCROWD_TOKEN")

    def available(self) -> bool:
        return bool(self._token())

    def blocked_reason(self) -> str:
        return "" if self.available() else "set BUGCROWD_API_TOKEN"

    def fetch(self) -> list[Program]:
        if not self.available():
            return []
        headers = {"Authorization": f"Token {self._token()}",
                   "Accept": "application/vnd.bugcrowd+json"}
        url = "https://api.bugcrowd.com/programs?page[limit]=100"
        out: list[Program] = []
        for _ in range(self.max_pages):
            data = self.fetch_json(url, headers=headers)
            for entry in (data.get("data") or []) if isinstance(data, dict) else []:
                prog = self.map_program(entry)
                if prog:
                    out.append(prog)
            nxt = ((data.get("links") or {}).get("next")) if isinstance(data, dict) else ""
            if not nxt:
                break
            url = nxt if str(nxt).startswith("http") else f"https://api.bugcrowd.com{nxt}"
        return out

    @staticmethod
    def map_program(entry: dict) -> Program | None:
        if not isinstance(entry, dict):
            return None
        a = entry.get("attributes") or {}
        code = str(a.get("code") or a.get("handle") or "").strip()
        name = str(a.get("name") or code).strip()
        if not code and not name:
            return None
        slug = code or name.lower().replace(" ", "-")
        repos, in_scope, out_scope = _repos_and_scope(
            a.get("in_scope") or a.get("targets") or [], a.get("out_of_scope") or [])
        now = _now_iso()
        return Program(
            handle=f"bugcrowd-{slug}", platform="bugcrowd",
            url=str((entry.get("links") or {}).get("self") or f"https://bugcrowd.com/{slug}"),
            targets=repos, out_of_scope=out_scope[:60],
            reward_ceiling=_num(a.get("max_reward") or a.get("reward_range_max")),
            scope_text=(_scope_text(in_scope, out_scope) or name)[:8000],
            source_retrieved_at=now, scope_retrieved_at=now,
            active=not bool(a.get("archived") or a.get("paused")))


@dataclass
class IntigritiConnector:
    name: str = "intigriti-api"
    fetch_json = staticmethod(_default_fetch_json)

    def _token(self) -> str:
        return _first_env("INTIGRITI_API_TOKEN", "INTIGRITI_TOKEN")

    def available(self) -> bool:
        return bool(self._token())

    def blocked_reason(self) -> str:
        return "" if self.available() else "set INTIGRITI_API_TOKEN"

    def fetch(self) -> list[Program]:
        if not self.available():
            return []
        headers = {"Authorization": f"Bearer {self._token()}", "Accept": "application/json"}
        data = self.fetch_json(
            "https://api.intigriti.com/external/researcher/v1/programs?limit=500", headers=headers)
        rows = data if isinstance(data, list) else (data.get("records") or data.get("data") or [])
        return [p for p in (self.map_program(e) for e in rows) if p]

    @staticmethod
    def map_program(entry: dict) -> Program | None:
        if not isinstance(entry, dict):
            return None
        handle = str(entry.get("handle") or entry.get("id") or "").strip()
        name = str(entry.get("name") or handle).strip()
        if not handle and not name:
            return None
        slug = handle or name.lower().replace(" ", "-")
        web = entry.get("webLinks") or entry.get("web_links") or {}
        url = str(web.get("detail") or web.get("self") or f"https://app.intigriti.com/programs/{slug}")
        repos, in_scope, out_scope = _repos_and_scope(
            entry.get("domains") or entry.get("in_scope") or [], entry.get("out_of_scope") or [])
        conf = str(entry.get("confidentialityLevel") or entry.get("confidentiality_level") or "")
        now = _now_iso()
        return Program(
            handle=f"intigriti-{slug}", platform="intigriti", url=url,
            targets=repos, out_of_scope=out_scope[:60],
            reward_ceiling=_num(entry.get("maxBounty") or entry.get("max_bounty")),
            scope_text=(_scope_text(in_scope, out_scope) or name)[:8000],
            source_retrieved_at=now, scope_retrieved_at=now,
            active=str(entry.get("status") or "open").lower() in ("open", "active", "1", "running"),
            notes=f"intigriti confidentiality={conf}" if conf else "")


@dataclass
class YesWeHackConnector:
    name: str = "yeswehack-api"
    fetch_json = staticmethod(_default_fetch_json)
    max_pages: int = 10

    def _token(self) -> str:
        return _first_env("YESWEHACK_API_TOKEN", "YWH_API_TOKEN")

    def available(self) -> bool:
        return bool(self._token())

    def blocked_reason(self) -> str:
        return "" if self.available() else "set YESWEHACK_API_TOKEN"

    def fetch(self) -> list[Program]:
        if not self.available():
            return []
        headers = {"Authorization": f"Bearer {self._token()}", "Accept": "application/json"}
        out: list[Program] = []
        page = 1
        for _ in range(self.max_pages):
            data = self.fetch_json(
                f"https://api.yeswehack.com/programs?page={page}&resultsPerPage=100",
                headers=headers)
            items = (data.get("items") or data.get("data") or []) if isinstance(data, dict) else []
            for e in items:
                prog = self.map_program(e)
                if prog:
                    out.append(prog)
            pg = (data.get("pagination") or {}) if isinstance(data, dict) else {}
            if not items or page >= int(pg.get("nb_pages") or page):
                break
            page += 1
        return out

    @staticmethod
    def map_program(entry: dict) -> Program | None:
        if not isinstance(entry, dict):
            return None
        slug = str(entry.get("slug") or entry.get("id") or "").strip()
        title = str(entry.get("title") or entry.get("name") or slug).strip()
        if not slug and not title:
            return None
        key = slug or title.lower().replace(" ", "-")
        scopes = entry.get("scopes") or entry.get("in_scope") or []
        repos, in_scope, out_scope = _repos_and_scope(scopes, entry.get("out_of_scope") or [])
        now = _now_iso()
        return Program(
            handle=f"yeswehack-{key}", platform="yeswehack",
            url=str(entry.get("url") or f"https://yeswehack.com/programs/{key}"),
            targets=repos, out_of_scope=out_scope[:60],
            reward_ceiling=_num(entry.get("max_bounty") or entry.get("bounty_reward_max")),
            scope_text=(_scope_text(in_scope, out_scope) or title)[:8000],
            source_retrieved_at=now, scope_retrieved_at=now,
            active=not bool(entry.get("disabled")) and str(
                entry.get("public_status") or entry.get("status") or "open").lower()
            not in ("suspended", "closed", "disabled"))


@dataclass
class ImmunefiConnector:
    name: str = "immunefi-api"

    def available(self) -> bool:
        return False

    def blocked_reason(self) -> str:
        return ("Immunefi exposes no official researcher API - add web3 programs manually "
                "or use an explicitly authorized public contest source")

    def fetch(self) -> list[Program]:
        return []


CONNECTORS: dict[str, type] = {
    "hackerone-api": HackerOneConnector,
    "bugcrowd-api": BugcrowdConnector,
    "intigriti-api": IntigritiConnector,
    "yeswehack-api": YesWeHackConnector,
    "immunefi-api": ImmunefiConnector,
}


def connector_status(names: list[str] | None = None) -> list[SourceStatus]:
    out: list[SourceStatus] = []
    for name in (names or list(CONNECTORS)):
        cls = CONNECTORS.get(name)
        if cls is None:
            continue
        src = cls()
        out.append(SourceStatus(name=name, available=src.available(),
                                blocked_reason=src.blocked_reason()))
    return out


@dataclass
class ConnectorImportResult:
    statuses: list[SourceStatus] = field(default_factory=list)
    programs: list[Program] = field(default_factory=list)


def fetch_connectors(names: list[str] | None = None) -> ConnectorImportResult:
    """Fetch available read-only connectors; blocked/erroring platforms never fail the import."""
    res = ConnectorImportResult()
    for name in (names or list(CONNECTORS)):
        cls = CONNECTORS.get(name)
        if cls is None:
            continue
        src = cls()
        if not src.available():
            res.statuses.append(SourceStatus(name=name, available=False,
                                             blocked_reason=src.blocked_reason()))
            continue
        try:
            progs = src.fetch()
            res.programs.extend(progs)
            res.statuses.append(SourceStatus(name=name, available=True, fetched=len(progs)))
        except Exception as exc:
            res.statuses.append(SourceStatus(name=name, available=True,
                                             error=f"{type(exc).__name__}: {exc}"[:160]))
    return res
