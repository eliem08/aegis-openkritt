"""Authenticated, first-party bounty-platform connectors.

These complement :mod:`aegis.ai.program_sources` (which reads the *public* bounty-targets-data
aggregator + Code4rena, no auth). A first-party connector pulls program/scope data directly from
a platform's own researcher API using the operator's credentials — which can include programs
and scope detail the public aggregator does not carry.

Boundaries (non-negotiable):
  * **Never invent credentials.** Each connector reads its token(s) from the environment. With no
    credentials it is *blocked*: ``fetch()`` returns ``[]`` and ``blocked_reason()`` explains what
    to set. It does NOT log in with guessed creds and does NOT scrape around authentication.
  * **Read-only.** Connectors only GET program/scope metadata. They never submit, accept invites,
    or take any action on the operator's behalf.
  * **Canonical output.** Every connector normalizes to :class:`aegis.ai.registry.Program`, so the
    rest of Aegis (registry, EV ranking, authorization ledger, hunt) has ONE representation and no
    per-platform hunting logic.

The request construction targets each platform's documented researcher API, and the
response→Program **mappers are unit-tested against representative fixtures**.

Validation status (be precise — do not overclaim):
  * **HackerOne — live-validated.** Confirmed against the live API with real credentials: the
    `/v1/hackers/programs` shape (``data``/``links``, ``attributes.{handle,name,submission_state,
    offers_bounties,policy,...}``) matches the mapper and it maps real programs. NOTE: the
    program-LIST endpoint carries no bounty amount and no scope assets, so ``reward_ceiling`` and
    ``targets`` stay empty until per-program detail / structured-scopes are fetched
    (``AEGIS_H1_FETCH_SCOPES=1``).
  * **Bugcrowd / Intigriti / YesWeHack — implemented + mapping-tested**, NOT yet live-validated
    (no credentials available here).
  * **Immunefi — no official API** (always blocked).

Response shapes are defensive (multiple key names, tolerate missing fields) so minor API drift
degrades gracefully rather than crashing an import.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from .program_sources import (
    _asset_str,
    _default_fetch_json,
    _num,
    _scope_text,
    repo_from_asset,
)
from .registry import Program


@runtime_checkable
class ProgramSource(Protocol):
    """Unified source interface. Public feeds and authenticated connectors both satisfy it."""
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


def _first_env(*names: str) -> str:
    for n in names:
        v = os.environ.get(n, "").strip()
        if v:
            return v
    return ""


def _repos_and_scope(in_items, out_items) -> tuple[list[str], list[str], list[str]]:
    """Shared: turn raw in/out scope items into (repos, in_scope_strs, out_scope_strs)."""
    in_scope = [s for s in (_asset_str(i) for i in (in_items or [])) if s]
    out_scope = [s for s in (_asset_str(i) for i in (out_items or [])) if s]
    repos: list[str] = []
    for s in in_scope:
        r = repo_from_asset(s)
        if r and r not in repos:
            repos.append(r)
    return repos, in_scope, out_scope


# --------------------------------------------------------------------------------------------
# HackerOne — https://api.hackerone.com/  (HTTP Basic: api_username:api_token)
# --------------------------------------------------------------------------------------------
@dataclass
class HackerOneConnector:
    name: str = "hackerone-api"
    fetch_json = staticmethod(_default_fetch_json)
    max_pages: int = 10

    def _auth(self) -> tuple[str, str] | None:
        u = _first_env("HACKERONE_API_USERNAME", "H1_API_USERNAME")
        t = _first_env("HACKERONE_API_TOKEN", "H1_API_TOKEN")
        return (u, t) if (u and t) else None

    def available(self) -> bool:
        return self._auth() is not None

    def blocked_reason(self) -> str:
        return "" if self.available() else (
            "set HACKERONE_API_USERNAME + HACKERONE_API_TOKEN "
            "(https://hackerone.com/settings/api_token - HTTP Basic auth)")

    def _headers(self) -> dict:
        u, t = self._auth()  # type: ignore[misc]
        tok = base64.b64encode(f"{u}:{t}".encode()).decode()
        return {"Authorization": f"Basic {tok}", "Accept": "application/json"}

    def fetch(self) -> list[Program]:
        if not self.available():
            return []
        headers = self._headers()
        max_pages = int(_first_env("AEGIS_H1_MAX_PAGES") or self.max_pages)
        url = "https://api.hackerone.com/v1/hackers/programs?page[size]=100"
        out: list[Program] = []
        want_scopes = _first_env("AEGIS_H1_FETCH_SCOPES") in ("1", "true", "yes")
        for _ in range(max_pages):
            try:
                data = self.fetch_json(url, headers=headers)
            except Exception:
                break                      # keep partial results rather than losing the import
            for entry in (data.get("data") or []) if isinstance(data, dict) else []:
                prog = self.map_program(entry)
                if prog is None:
                    continue
                # only spend a per-program structured-scopes call on ACTIVE programs — inactive
                # ones are blocked by the authorization gate anyway, so their scopes are wasted.
                if want_scopes and prog.active:
                    try:
                        sd = self.fetch_json(
                            f"https://api.hackerone.com/v1/hackers/programs/"
                            f"{prog.handle}/structured_scopes?page[size]=100", headers=headers)
                        self.apply_scopes(prog, sd)
                    except Exception:
                        pass
                out.append(prog)
            nxt = ((data.get("links") or {}).get("next")) if isinstance(data, dict) else ""
            if not nxt:
                break
            url = nxt
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
            handle=handle, platform="hackerone", url=f"https://hackerone.com/{handle}",
            reward_ceiling=_num(a.get("max_bounty") or a.get("base_bounty")),
            active=(state == "open") and bool(a.get("offers_bounties", True)),
            scope_text=str(a.get("policy") or a.get("name") or handle)[:8000],
            notes="HackerOne API; run with AEGIS_H1_FETCH_SCOPES=1 to populate in/out-of-scope")

    @staticmethod
    def apply_scopes(prog: Program, scopes_data: dict) -> Program:
        """Fold a program's structured_scopes response into targets/out_of_scope/scope_text."""
        rows = (scopes_data.get("data") or []) if isinstance(scopes_data, dict) else []
        in_items, out_items = [], []
        for r in rows:
            at = (r.get("attributes") or {}) if isinstance(r, dict) else {}
            ident = str(at.get("asset_identifier") or "")
            if not ident:
                continue
            (in_items if at.get("eligible_for_submission", True) else out_items).append(ident)
        repos, in_scope, out_scope = _repos_and_scope(in_items, out_items)
        if repos:
            prog.targets = repos
        if out_scope:
            prog.out_of_scope = out_scope[:60]
        prog.scope_text = (_scope_text(in_scope, out_scope) or prog.scope_text)[:8000]
        return prog


# --------------------------------------------------------------------------------------------
# Bugcrowd — https://api.bugcrowd.com/  (Authorization: Token <token>, vendor accept header)
# --------------------------------------------------------------------------------------------
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
        return "" if self.available() else (
            "set BUGCROWD_API_TOKEN (Bugcrowd researcher API token; "
            "requires API access on your account)")

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
        # scope may arrive inline as targets/scope, or require a follow-up call; map what's here.
        repos, in_scope, out_scope = _repos_and_scope(
            a.get("in_scope") or a.get("targets") or [], a.get("out_of_scope") or [])
        return Program(
            handle=f"bugcrowd-{slug}", platform="bugcrowd",
            url=str((entry.get("links") or {}).get("self") or f"https://bugcrowd.com/{slug}"),
            targets=repos, out_of_scope=out_scope[:60],
            reward_ceiling=_num(a.get("max_reward") or a.get("reward_range_max")),
            scope_text=(_scope_text(in_scope, out_scope) or name)[:8000],
            active=not bool(a.get("archived") or a.get("paused")))


# --------------------------------------------------------------------------------------------
# Intigriti — https://api.intigriti.com/external/researcher/v1/  (Authorization: Bearer <token>)
# --------------------------------------------------------------------------------------------
@dataclass
class IntigritiConnector:
    name: str = "intigriti-api"
    fetch_json = staticmethod(_default_fetch_json)

    def _token(self) -> str:
        return _first_env("INTIGRITI_API_TOKEN", "INTIGRITI_TOKEN")

    def available(self) -> bool:
        return bool(self._token())

    def blocked_reason(self) -> str:
        return "" if self.available() else (
            "set INTIGRITI_API_TOKEN (Intigriti researcher API bearer token)")

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
        return Program(
            handle=f"intigriti-{slug}", platform="intigriti", url=url,
            targets=repos, out_of_scope=out_scope[:60],
            reward_ceiling=_num(entry.get("maxBounty") or entry.get("max_bounty")),
            scope_text=(_scope_text(in_scope, out_scope) or name)[:8000],
            active=str(entry.get("status") or "open").lower() in ("open", "active", "1", "running"),
            notes=f"intigriti confidentiality={conf}" if conf else "")


# --------------------------------------------------------------------------------------------
# YesWeHack — https://api.yeswehack.com/  (Authorization: Bearer <JWT/API token>)
# --------------------------------------------------------------------------------------------
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
        return "" if self.available() else (
            "set YESWEHACK_API_TOKEN (YesWeHack API JWT/token; obtain via YWH account API)")

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
        return Program(
            handle=f"yeswehack-{key}", platform="yeswehack",
            url=str(entry.get("url") or f"https://yeswehack.com/programs/{key}"),
            targets=repos, out_of_scope=out_scope[:60],
            reward_ceiling=_num(entry.get("max_bounty") or entry.get("bounty_reward_max")),
            scope_text=(_scope_text(in_scope, out_scope) or title)[:8000],
            active=not bool(entry.get("disabled")) and str(
                entry.get("public_status") or entry.get("status") or "open").lower()
            not in ("suspended", "closed", "disabled"))


# --------------------------------------------------------------------------------------------
# Immunefi — no official public/researcher API; always blocked (add manually or via Code4rena).
# --------------------------------------------------------------------------------------------
@dataclass
class ImmunefiConnector:
    name: str = "immunefi-api"

    def available(self) -> bool:
        return False

    def blocked_reason(self) -> str:
        return ("Immunefi exposes no official researcher API - add web3 programs manually "
                "(paste scope into the registry) or hunt their public contest code via Code4rena")

    def fetch(self) -> list[Program]:
        return []


#: authenticated connectors, keyed by source name. Registered into the unified source set.
CONNECTORS: dict[str, type] = {
    "hackerone-api": HackerOneConnector,
    "bugcrowd-api": BugcrowdConnector,
    "intigriti-api": IntigritiConnector,
    "yeswehack-api": YesWeHackConnector,
    "immunefi-api": ImmunefiConnector,
}


def connector_status(names: list[str] | None = None) -> list[SourceStatus]:
    """Availability of each connector WITHOUT fetching — so the operator/UI can see which are
    usable and which are blocked (and why) at a glance. Never touches the network."""
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
    """Fetch every AVAILABLE connector; record blocked ones with reasons; never fail the whole
    import because one platform is blocked or erroring (per the multi-source contract)."""
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
