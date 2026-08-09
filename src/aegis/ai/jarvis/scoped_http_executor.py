"""Grant-bound HTTP execution through the canonical scoped egress service."""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from threading import Lock
from urllib.parse import urlsplit

import httpx

from aegis.ai.agentic_os import AuthorizationEnvelope

from .execution_errors import MissionBackendUnavailableError

POLICY_ACTION = "hunter.http.execute"
TokenIssuer = Callable[[str, str, str, AuthorizationEnvelope], str]


@dataclass(frozen=True, slots=True)
class ScopedHttpResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes
    final_url: str
    redirects: int


class ScopedEgressHttpExecutor:
    """Execute bounded HTTP requests without giving workers direct network access."""

    def __init__(
        self,
        endpoint: str,
        *,
        token_issuer: TokenIssuer,
        grant_verifier,
        timeout_seconds: float = 15.0,
        max_requests: int = 20,
        max_request_bytes: int = 1_048_576,
        max_response_bytes: int = 2_097_152,
        client=None,
    ) -> None:
        parts = urlsplit(endpoint)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("scoped egress endpoint must be HTTP(S)")
        self.endpoint = endpoint.rstrip("/") + "/v1/fetch"
        self.token_issuer = token_issuer
        self.grant_verifier = grant_verifier
        self.timeout_seconds = timeout_seconds
        self.max_requests = max_requests
        self.max_request_bytes = max_request_bytes
        self.max_response_bytes = max_response_bytes
        self.client = client
        self.requests = 0
        self._budget_lock = Lock()

    def request(
        self,
        method: str,
        url: str,
        *,
        authorization: AuthorizationEnvelope,
        headers: Mapping[str, str] | None = None,
        body: bytes = b"",
    ) -> ScopedHttpResponse:
        grant = authorization.grant
        if (
            grant is None
            or grant.scope_digest != authorization.scope_digest
            or not grant.verify(self.grant_verifier)
            or not grant.network_allowed
        ):
            raise PermissionError("HTTP execution requires a verified scope-bound network grant")
        normalized_method = method.upper()
        if normalized_method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("unsupported HTTP method")
        if len(body) > self.max_request_bytes:
            raise ValueError("HTTP request body exceeded executor size budget")
        authorized_limit = min(
            max(0, authorization.budget.max_requests),
            max(0, grant.budget.max_requests),
            self.max_requests,
        )
        with self._budget_lock:
            if self.requests >= authorized_limit:
                raise RuntimeError("HTTP execution request budget exhausted")
            self.requests += 1
        token = self.token_issuer(POLICY_ACTION, normalized_method, url, authorization)
        if not token:
            raise PermissionError("egress token issuer refused the HTTP destination")
        payload = {
            "method": normalized_method,
            "url": url,
            "headers": dict(headers or {}),
            "body_base64": base64.b64encode(body).decode("ascii") if body else None,
        }
        try:
            if self.client is not None:
                response = self.client.post(
                    self.endpoint,
                    json=payload,
                    headers={"authorization": f"Bearer {token}"},
                    timeout=self.timeout_seconds,
                )
            else:
                with httpx.Client(timeout=self.timeout_seconds, trust_env=False) as client:
                    response = client.post(
                        self.endpoint,
                        json=payload,
                        headers={"authorization": f"Bearer {token}"},
                    )
            response.raise_for_status()
            document = response.json()
            decoded = base64.b64decode(document["body_base64"], validate=True)
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
            raise MissionBackendUnavailableError(
                f"scoped egress failed to produce a valid response: {exc}"
            ) from exc
        if len(decoded) > self.max_response_bytes:
            raise MissionBackendUnavailableError("HTTP response exceeded executor size budget")
        return ScopedHttpResponse(
            status_code=int(document["status_code"]),
            headers=dict(document.get("headers") or {}),
            body=decoded,
            final_url=str(document.get("final_url") or url),
            redirects=int(document.get("redirects") or 0),
        )


__all__ = ["POLICY_ACTION", "ScopedEgressHttpExecutor", "ScopedHttpResponse", "TokenIssuer"]
