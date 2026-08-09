from __future__ import annotations

import base64

import pytest

from aegis.ai.agentic_os import (
    AuthorizationEnvelope,
    Budget,
    mint_execution_grant,
    process_grant_verifier,
)
from aegis.ai.jarvis.scoped_artifact_fetcher import POLICY_ACTION, ScopedEgressArtifactFetcher


class Response:
    def __init__(self, body=b"bundle"):
        self.body = body

    def raise_for_status(self):
        return None

    def json(self):
        return {
            "status_code": 200, "headers": {"content-type": "application/javascript"},
            "body_base64": base64.b64encode(self.body).decode(),
        }


class Client:
    def __init__(self, response=None):
        self.response = response or Response()
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


def authorization():
    verifier = process_grant_verifier()
    budget = Budget(max_cost_usd=1, max_requests=3, max_human_minutes=1)
    grant = mint_execution_grant(
        type("Allowed", (), {"allowed": True})(), scope_digest="scope:assets",
        budget=budget, verifier=verifier, network=True,
    )
    return verifier, AuthorizationEnvelope(
        scope_digest="scope:assets", budget=budget, grant=grant,
    )


def test_fetcher_requires_signed_grant_and_uses_exact_policy_action():
    verifier, auth = authorization()
    issued = []
    client = Client()
    fetcher = ScopedEgressArtifactFetcher(
        "http://egress.internal", grant_verifier=verifier, client=client,
        token_issuer=lambda action, url, envelope: issued.append(
            (action, url, envelope.scope_digest)
        ) or "signed-token",
    )
    status, headers, body = fetcher.get_authorized("https://app.example/app.js", auth)
    assert (status, body) == (200, b"bundle")
    assert headers["content-type"] == "application/javascript"
    assert issued == [(POLICY_ACTION, "https://app.example/app.js", "scope:assets")]
    assert client.calls[0][1]["headers"] == {"authorization": "Bearer signed-token"}
    with pytest.raises(PermissionError, match="bound authorization"):
        fetcher.get("https://app.example/app.js")


def test_fetcher_fails_closed_on_bad_grant_budget_and_oversize_response():
    verifier, auth = authorization()
    fetcher = ScopedEgressArtifactFetcher(
        "http://egress.internal", grant_verifier=verifier, client=Client(), max_requests=1,
        token_issuer=lambda *_: "token",
    )
    with pytest.raises(PermissionError, match="network grant"):
        fetcher.get_authorized(
            "https://app.example/a.js", AuthorizationEnvelope(scope_digest="scope:assets")
        )
    fetcher.get_authorized("https://app.example/a.js", auth)
    with pytest.raises(RuntimeError, match="budget exhausted"):
        fetcher.get_authorized("https://app.example/b.js", auth)

    oversized = ScopedEgressArtifactFetcher(
        "http://egress.internal", grant_verifier=verifier,
        client=Client(Response(b"xx")), max_response_bytes=1,
        token_issuer=lambda *_: "token",
    )
    with pytest.raises(RuntimeError, match="size budget"):
        oversized.get_authorized("https://app.example/a.js", auth)
