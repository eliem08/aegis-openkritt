"""Grant-bound client for the canonical scoped egress artifact-fetch path."""

from __future__ import annotations

import base64
from collections.abc import Callable
from urllib.parse import urlsplit

import httpx

from aegis.ai.agentic_os import AuthorizationEnvelope

POLICY_ACTION = "hunter.artifact.fetch"
TokenIssuer = Callable[[str, str, AuthorizationEnvelope], str]


class ScopedEgressArtifactFetcher:
    """Fetch artifacts only through `/v1/fetch` with a destination-bound token."""

    def __init__(
        self, endpoint: str, *, token_issuer: TokenIssuer, grant_verifier,
        timeout_seconds: float = 15.0, max_requests: int = 100,
        max_response_bytes: int = 2_097_152, client=None,
    ) -> None:
        parts = urlsplit(endpoint)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("scoped egress endpoint must be HTTP(S)")
        self.endpoint = endpoint.rstrip("/") + "/v1/fetch"
        self.token_issuer = token_issuer
        self.grant_verifier = grant_verifier
        self.timeout_seconds = timeout_seconds
        self.max_requests = max_requests
        self.max_response_bytes = max_response_bytes
        self.client = client
        self.requests = 0

    def get(self, _url: str):
        raise PermissionError("artifact fetch requires a bound authorization envelope")

    def get_authorized(self, url: str, authorization: AuthorizationEnvelope):
        grant = authorization.grant
        if (grant is None or grant.scope_digest != authorization.scope_digest
                or not grant.verify(self.grant_verifier) or not grant.network_allowed):
            raise PermissionError("artifact fetch requires a verified scope-bound network grant")
        authorized_limit = max(0, authorization.budget.max_requests)
        request_limit = min(self.max_requests, authorized_limit)
        if self.requests >= request_limit:
            raise RuntimeError("artifact request budget exhausted")
        token = self.token_issuer(POLICY_ACTION, url, authorization)
        if not token:
            raise PermissionError("egress token issuer refused the artifact destination")
        self.requests += 1
        payload = {"method": "GET", "url": url, "headers": {"accept": "*/*"}}
        headers = {"authorization": f"Bearer {token}"}
        if self.client is not None:
            response = self.client.post(
                self.endpoint, json=payload, headers=headers, timeout=self.timeout_seconds,
            )
        else:
            with httpx.Client(timeout=self.timeout_seconds, trust_env=False) as client:
                response = client.post(self.endpoint, json=payload, headers=headers)
        response.raise_for_status()
        document = response.json()
        try:
            body = base64.b64decode(document["body_base64"], validate=True)
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("scoped egress returned an invalid body") from exc
        if len(body) > self.max_response_bytes:
            raise RuntimeError("artifact response exceeded client size budget")
        return int(document["status_code"]), dict(document.get("headers") or {}), body


__all__ = ["POLICY_ACTION", "ScopedEgressArtifactFetcher"]
