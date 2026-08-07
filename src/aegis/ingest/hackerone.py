"""HackerOne connector — read-only discovery of authorized programs (§4, §5).

Talks to the HackerOne *Hacker API* (https://api.hackerone.com/v1/hackers/...)
using HTTP Basic auth with the hacker's API username + token. Only GET requests
are issued — this is passive discovery of scope and rules, never active testing.

Credentials are read from the environment (``HACKERONE_API_USERNAME`` /
``HACKERONE_API_TOKEN``) and passed straight to the HTTP client; they are never
logged. Requires ``httpx`` (api/dev extras).

The client returns raw JSON:API payloads; :func:`map_program` turns a program
detail + its structured scopes into a platform-agnostic
:class:`~aegis.ingest.program.ProgramRules`.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable

import httpx

from .program import (
    ProgramRules,
    ScopeAsset,
    classify_asset_type,
    parse_policy_constraints,
)

HACKERONE_BASE_URL = "https://api.hackerone.com"
USER_AGENT = "aegis-ingest/0.2 (+authorized-bug-bounty-tooling)"

# Transient statuses worth retrying (rate limit + gateway/server errors).
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})


class HackerOneAuthError(RuntimeError):
    """Raised when API credentials are missing."""


class HackerOneClient:
    def __init__(
        self,
        *,
        username: str,
        token: str,
        base_url: str = HACKERONE_BASE_URL,
        client: httpx.Client | None = None,
        timeout: float = 20.0,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not username or not token:
            raise HackerOneAuthError("HackerOne API username and token are required")
        self._owns_client = client is None
        self._client = client or httpx.Client(
            base_url=base_url,
            auth=(username, token),
            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
            timeout=timeout,
        )
        self._max_retries = max_retries
        self._backoff_factor = backoff_factor
        self._sleep = sleep

    def _get(self, path: str) -> httpx.Response:
        """GET with retry/backoff on transient errors; honours Retry-After.

        Rate limits (429) and 5xx are retried up to ``max_retries`` times with
        exponential backoff; everything else (incl. 401/403/404) is surfaced
        immediately via ``raise_for_status``.
        """
        attempt = 0
        while True:
            response = self._client.get(path)
            if response.status_code in RETRYABLE_STATUS and attempt < self._max_retries:
                self._sleep(self._retry_delay(response, attempt))
                attempt += 1
                continue
            response.raise_for_status()
            return response

    def _retry_delay(self, response: httpx.Response, attempt: int) -> float:
        retry_after = response.headers.get("retry-after")
        if retry_after and retry_after.strip().isdigit():
            return float(retry_after)
        return self._backoff_factor * (2 ** attempt)

    @classmethod
    def from_env(cls, env: dict | None = None, **kwargs) -> HackerOneClient:
        env = env if env is not None else os.environ
        username = env.get("HACKERONE_API_USERNAME", "")
        token = env.get("HACKERONE_API_TOKEN", "")
        if not username or not token:
            raise HackerOneAuthError(
                "set HACKERONE_API_USERNAME and HACKERONE_API_TOKEN in the environment"
            )
        return cls(username=username, token=token, **kwargs)

    # -- read-only endpoints --

    def list_programs(self, max_pages: int = 10) -> list[dict]:
        """GET /v1/hackers/programs — programs the account can access."""
        items: list[dict] = []
        path: str | None = "/v1/hackers/programs"
        pages = 0
        while path and pages < max_pages:
            body = self._get(path).json()
            items.extend(body.get("data", []))
            path = (body.get("links") or {}).get("next")
            # `next` may be an absolute URL; httpx handles it as a full URL.
            pages += 1
        return items

    def get_program(self, handle: str) -> dict:
        """GET /v1/hackers/programs/{handle} — program detail (incl. policy)."""
        return self._get(f"/v1/hackers/programs/{handle}").json()

    def get_structured_scopes(self, handle: str, max_pages: int = 20) -> list[dict]:
        """GET /v1/hackers/programs/{handle}/structured_scopes (paginated)."""
        items: list[dict] = []
        path: str | None = f"/v1/hackers/programs/{handle}/structured_scopes"
        pages = 0
        while path and pages < max_pages:
            body = self._get(path).json()
            items.extend(body.get("data", []))
            path = (body.get("links") or {}).get("next")
            pages += 1
        return items

    def list_my_reports(self, max_pages: int = 20) -> list[dict]:
        """GET /v1/hackers/me/reports — the authenticated hacker's own reports.

        Read-only. Each report carries ``attributes.state`` (resolved, duplicate,
        not-applicable, informative, triaged, …), which the learning loop maps to a
        verdict. Paginated like the other Hacker-API endpoints.
        """
        items: list[dict] = []
        path: str | None = "/v1/hackers/me/reports"
        pages = 0
        while path and pages < max_pages:
            body = self._get(path).json()
            items.extend(body.get("data", []))
            path = (body.get("links") or {}).get("next")
            pages += 1
        return items

    def fetch_program_rules(self, handle: str) -> ProgramRules:
        """Convenience: detail + scopes -> ProgramRules in one call."""
        detail = self.get_program(handle)
        scopes = self.get_structured_scopes(handle)
        return map_program(detail, scopes)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> HackerOneClient:
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# --- mapping --------------------------------------------------------------

def _scope_from_json(entry: dict) -> ScopeAsset:
    attrs = entry.get("attributes", {})
    raw_type = attrs.get("asset_type", "OTHER")
    identifier = attrs.get("asset_identifier", "")
    return ScopeAsset(
        identifier=identifier,
        asset_type=classify_asset_type(raw_type, identifier),
        raw_asset_type=raw_type,
        eligible_for_submission=bool(attrs.get("eligible_for_submission", False)),
        eligible_for_bounty=bool(attrs.get("eligible_for_bounty", False)),
        max_severity=attrs.get("max_severity"),
        instruction=attrs.get("instruction", "") or "",
    )


def map_program(program_detail: dict, structured_scopes: list[dict]) -> ProgramRules:
    """Map a HackerOne program detail + structured scopes -> ProgramRules."""
    data = program_detail.get("data", program_detail)
    attrs = data.get("attributes", {})
    handle = attrs.get("handle", "")
    policy_text = attrs.get("policy", "") or ""

    in_scope: list[ScopeAsset] = []
    out_of_scope: list[ScopeAsset] = []
    for entry in structured_scopes:
        asset = _scope_from_json(entry)
        if asset.eligible_for_submission:
            in_scope.append(asset)
        else:
            out_of_scope.append(asset)

    constraints = parse_policy_constraints(policy_text)

    return ProgramRules(
        platform="hackerone",
        handle=handle,
        name=attrs.get("name", handle),
        submission_state=attrs.get("submission_state", "open"),
        offers_bounties=bool(attrs.get("offers_bounties", False)),
        policy_text=policy_text,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
        automation_allowed=constraints["automation_allowed"],
        ai_allowed=constraints["ai_allowed"],
        rate_limit_rps=constraints["rate_limit_rps"],
        notes=constraints["notes"],
    )
