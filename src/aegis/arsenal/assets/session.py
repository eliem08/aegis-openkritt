"""The single outbound choke point for every asset technique.

Every request an asset lane makes goes through :class:`HuntSession`, which enforces
the guardrails in one place instead of trusting each technique to remember them:

* **Scope.** The destination is checked against the operator's allowlist before the
  socket is opened, and redirects are *not* followed — a 302 is returned as data,
  because following it would move the request to a host the allowlist never saw.
* **Read-only by default.** Only ``GET``, ``HEAD``, and ``OPTIONS`` are permitted
  unless the operator passes ``allow_state_change``. There is no per-technique
  override.
* **Rate limiting.** A conservative token-spacing limiter plus a hard request
  budget, so a lane cannot resemble a denial-of-service attempt.
* **No credentials.** The session refuses to send ``Authorization``/``Cookie``
  headers it was not explicitly handed by the operator, never prompts for or
  stores credentials, and never attempts account creation or CAPTCHA solving.
* **Auditable.** Every attempt — allowed, refused, throttled, or failed — appends
  a structured record, optionally to a JSONL file, so activity is reviewable after
  the fact.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .scope import OutOfScopeError, ScopeAllowlist

#: Methods that cannot change server state. Anything else needs an explicit opt-in.
READ_ONLY_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})

#: Header names the session will never populate on its own behalf.
CREDENTIAL_HEADERS: frozenset[str] = frozenset({
    "authorization", "cookie", "proxy-authorization", "x-api-key", "x-auth-token",
})

DEFAULT_USER_AGENT = "aegis-arsenal/0.7 (authorized bug-bounty research; contact via program)"


class BudgetExhausted(RuntimeError):
    """The session's request budget is spent; the lane must stop rather than continue."""


class StateChangeRefused(PermissionError):
    """A technique asked for a state-changing method without the operator opt-in."""


class InteractionRequired(RuntimeError):
    """A flow needs credentials, account creation, or a CAPTCHA — the operator must act.

    Raised instead of attempting any of those. The message is written to be pasted
    straight to the operator so they know exactly what is blocking the lane.
    """


@dataclass(frozen=True, slots=True)
class RequestRecord:
    """One auditable outbound attempt."""

    sequence: int
    observed_at: str
    method: str
    destination: str
    host: str
    technique_id: str
    outcome: str
    status_code: int | None = None
    scope_rule: str = ""
    reason: str = ""
    elapsed_ms: int = 0
    response_bytes: int = 0

    def document(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """A response body plus the metadata the lanes reason about."""

    status_code: int
    url: str
    headers: Mapping[str, str]
    body: bytes
    elapsed_ms: int

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.text)

    def header(self, name: str) -> str:
        lowered = name.lower()
        for key, value in self.headers.items():
            if key.lower() == lowered:
                return value
        return ""


@dataclass(frozen=True, slots=True)
class RateLimit:
    """Conservative defaults: well under one request per second, hard total cap."""

    requests_per_second: float = 0.5
    max_requests: int = 200
    timeout_seconds: float = 15.0

    def __post_init__(self) -> None:
        if self.requests_per_second <= 0 or self.requests_per_second > 10:
            raise ValueError("requests_per_second must be in (0, 10]")
        if self.max_requests <= 0:
            raise ValueError("max_requests must be positive")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

    @property
    def min_interval(self) -> float:
        return 1.0 / self.requests_per_second


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Return redirects as responses. Following one could leave the allowlist."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def _default_transport(
    request: urllib.request.Request, timeout: float,
) -> tuple[int, Mapping[str, str], bytes]:
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, dict(response.headers.items()), response.read()
    except urllib.error.HTTPError as error:
        # 4xx/5xx and un-followed redirects are legitimate observations, not failures.
        body = error.read() if error.fp is not None else b""
        return error.code, dict(error.headers.items() if error.headers else {}), body


Transport = Callable[[urllib.request.Request, float], tuple[int, Mapping[str, str], bytes]]


@dataclass
class HuntSession:
    """Scope-enforcing, rate-limited, read-only-by-default outbound session."""

    allowlist: ScopeAllowlist
    rate_limit: RateLimit = field(default_factory=RateLimit)
    allow_state_change: bool = False
    operator_headers: Mapping[str, str] = field(default_factory=dict)
    log_path: str | Path | None = None
    user_agent: str = DEFAULT_USER_AGENT
    transport: Transport = _default_transport
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic
    _records: list[RequestRecord] = field(default_factory=list, init=False)
    _last_request_at: float | None = field(default=None, init=False)
    _sequence: int = field(default=0, init=False)

    @property
    def records(self) -> tuple[RequestRecord, ...]:
        return tuple(self._records)

    @property
    def requests_made(self) -> int:
        return sum(item.outcome == "completed" for item in self._records)

    @property
    def remaining_budget(self) -> int:
        return max(0, self.rate_limit.max_requests - self.requests_made)

    def require_operator_action(self, technique_id: str, what: str) -> None:
        """Stop the lane and tell the operator what only they may do."""
        self._append(RequestRecord(
            self._next_sequence(), _now(), "-", "-", "-", technique_id,
            "operator_action_required", reason=what,
        ))
        raise InteractionRequired(
            f"technique {technique_id!r} cannot continue automatically: {what}. "
            "Aegis does not enter credentials, create accounts, or solve CAPTCHAs — "
            "perform this step yourself and re-run with the resulting artifact."
        )

    def authorize_connection(
        self, destination: str, *, technique_id: str, protocol: str = "TCP",
    ) -> str:
        """Scope-check and budget-check a non-HTTP connection (TLS, port probe, resolver).

        Techniques that do not speak HTTP still have to pass the same gate, and the
        attempt still has to land in the audit log. Returns the bare host on success.
        """
        decision = self.allowlist.evaluate(destination)
        if not decision.allowed:
            self._append(RequestRecord(
                self._next_sequence(), _now(), protocol, destination, decision.host,
                technique_id, "refused_out_of_scope", reason=decision.reason,
            ))
            raise OutOfScopeError(destination, decision.reason)
        if self.requests_made >= self.rate_limit.max_requests:
            self._append(RequestRecord(
                self._next_sequence(), _now(), protocol, destination, decision.host,
                technique_id, "refused_budget_exhausted",
                scope_rule=decision.matched_rule, reason="request budget is spent",
            ))
            raise BudgetExhausted("request budget is spent")
        self._throttle()
        self._last_request_at = self.clock()
        self._append(RequestRecord(
            self._next_sequence(), _now(), protocol, destination, decision.host,
            technique_id, "completed", scope_rule=decision.matched_rule,
        ))
        return decision.host

    def request(
        self,
        method: str,
        url: str,
        *,
        technique_id: str,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        host_override: str = "",
    ) -> HttpResponse:
        """Perform one guarded request, or raise with an audited refusal record."""
        verb = (method or "").upper()
        if verb not in READ_ONLY_METHODS and not self.allow_state_change:
            self._append(RequestRecord(
                self._next_sequence(), _now(), verb, url, "", technique_id, "refused",
                reason="state-changing method requires the explicit --allow-state-change opt-in",
            ))
            raise StateChangeRefused(
                f"{verb} is state-changing; re-run with the explicit state-change opt-in "
                "if the program authorizes it"
            )

        decision = self.allowlist.evaluate(url)
        if not decision.allowed:
            self._append(RequestRecord(
                self._next_sequence(), _now(), verb, url, decision.host, technique_id,
                "refused_out_of_scope", scope_rule="", reason=decision.reason,
            ))
            raise OutOfScopeError(url, decision.reason)

        if self.requests_made >= self.rate_limit.max_requests:
            self._append(RequestRecord(
                self._next_sequence(), _now(), verb, url, decision.host, technique_id,
                "refused_budget_exhausted", scope_rule=decision.matched_rule,
                reason=f"request budget of {self.rate_limit.max_requests} is spent",
            ))
            raise BudgetExhausted(
                f"request budget of {self.rate_limit.max_requests} is spent; "
                "raise it deliberately rather than looping"
            )

        self._throttle()
        request = urllib.request.Request(
            url, data=body, method=verb, headers=self._headers(headers, host_override),
        )
        started = self.clock()
        try:
            status, response_headers, payload = self.transport(
                request, self.rate_limit.timeout_seconds,
            )
        except Exception as exc:
            self._append(RequestRecord(
                self._next_sequence(), _now(), verb, url, decision.host, technique_id,
                "transport_error", scope_rule=decision.matched_rule,
                reason=f"{type(exc).__name__}: {exc}",
                elapsed_ms=_elapsed_ms(started, self.clock()),
            ))
            raise
        elapsed = _elapsed_ms(started, self.clock())
        self._last_request_at = self.clock()
        self._append(RequestRecord(
            self._next_sequence(), _now(), verb, url, decision.host, technique_id,
            "completed", status_code=status, scope_rule=decision.matched_rule,
            elapsed_ms=elapsed, response_bytes=len(payload),
        ))
        return HttpResponse(status, url, dict(response_headers), payload, elapsed)

    def get(self, url: str, *, technique_id: str, **kwargs: Any) -> HttpResponse:
        return self.request("GET", url, technique_id=technique_id, **kwargs)

    def head(self, url: str, *, technique_id: str, **kwargs: Any) -> HttpResponse:
        return self.request("HEAD", url, technique_id=technique_id, **kwargs)

    def audit_log(self) -> list[dict[str, Any]]:
        return [item.document() for item in self._records]

    def _headers(
        self, supplied: Mapping[str, str] | None, host_override: str,
    ) -> dict[str, str]:
        headers = {"User-Agent": self.user_agent, "Accept": "*/*"}
        # Operator-supplied credential headers are honored because the operator
        # chose them; nothing else may introduce one.
        for source in (self.operator_headers, supplied or {}):
            for key, value in source.items():
                if key.lower() in CREDENTIAL_HEADERS and source is not self.operator_headers:
                    continue
                headers[key] = value
        if host_override:
            headers["Host"] = host_override
        return headers

    def _throttle(self) -> None:
        if self._last_request_at is None:
            return
        waited = self.clock() - self._last_request_at
        remaining = self.rate_limit.min_interval - waited
        if remaining > 0:
            self.sleep(remaining)

    def _next_sequence(self) -> int:
        self._sequence += 1
        return self._sequence

    def _append(self, record: RequestRecord) -> None:
        self._records.append(record)
        if not self.log_path:
            return
        path = Path(self.log_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record.document(), sort_keys=True) + "\n")


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _elapsed_ms(started: float, finished: float) -> int:
    return max(0, int((finished - started) * 1000))


def summarize_requests(records: Sequence[RequestRecord]) -> dict[str, Any]:
    """A compact, non-sensitive rollup for the hunt report."""
    outcomes: dict[str, int] = {}
    for record in records:
        outcomes[record.outcome] = outcomes.get(record.outcome, 0) + 1
    return {
        "total_attempts": len(records),
        "outcomes": dict(sorted(outcomes.items())),
        "hosts_contacted": sorted({item.host for item in records
                                   if item.host and item.outcome == "completed"}),
    }


__all__ = [
    "BudgetExhausted",
    "CREDENTIAL_HEADERS",
    "DEFAULT_USER_AGENT",
    "HttpResponse",
    "HuntSession",
    "InteractionRequired",
    "READ_ONLY_METHODS",
    "RateLimit",
    "RequestRecord",
    "StateChangeRefused",
    "summarize_requests",
]
