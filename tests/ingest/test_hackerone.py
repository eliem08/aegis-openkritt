from datetime import datetime, timedelta, timezone

import httpx
import pytest

from aegis.ingest import HackerOneAuthError, HackerOneClient, ProgramRules, map_program
from aegis.policy import (
    ActionRequest,
    Authorization,
    HmacSignatureVerifier,
    PolicyEngine,
    Verdict,
)

PROGRAM_DETAIL = {
    "data": {
        "id": "1",
        "type": "program",
        "attributes": {
            "handle": "acme",
            "name": "Acme",
            "submission_state": "open",
            "offers_bounties": True,
            "policy": "Automated scanning is prohibited. Limit to 3 requests per second.",
        },
    }
}

STRUCTURED_SCOPES_P1 = {
    "data": [
        {"id": "1", "type": "structured-scope", "attributes": {
            "asset_type": "URL", "asset_identifier": "api.acme.test",
            "eligible_for_submission": True, "eligible_for_bounty": True}},
    ],
    "links": {"next": "https://api.hackerone.com/v1/hackers/programs/acme/structured_scopes?page[number]=2"},
}
STRUCTURED_SCOPES_P2 = {
    "data": [
        {"id": "2", "type": "structured-scope", "attributes": {
            "asset_type": "URL", "asset_identifier": "*.acme.test",
            "eligible_for_submission": True, "eligible_for_bounty": True}},
    ],
    "links": {},
}

seen_auth: list[str] = []


def _handler(request: httpx.Request) -> httpx.Response:
    seen_auth.append(request.headers.get("authorization", ""))
    path = request.url.path
    page = request.url.params.get("page[number]")
    if path == "/v1/hackers/programs":
        if page == "2":
            return httpx.Response(200, json={"data": [{"id": "2", "type": "program", "attributes": {"handle": "beta"}}], "links": {}})
        return httpx.Response(200, json={"data": [{"id": "1", "type": "program", "attributes": {"handle": "acme"}}],
                                         "links": {"next": "https://api.hackerone.com/v1/hackers/programs?page[number]=2"}})
    if path == "/v1/hackers/programs/acme":
        return httpx.Response(200, json=PROGRAM_DETAIL)
    if path == "/v1/hackers/programs/acme/structured_scopes":
        return httpx.Response(200, json=STRUCTURED_SCOPES_P2 if page == "2" else STRUCTURED_SCOPES_P1)
    return httpx.Response(404, json={"errors": []})


@pytest.fixture
def client() -> HackerOneClient:
    seen_auth.clear()
    http = httpx.Client(
        transport=httpx.MockTransport(_handler),
        base_url="https://api.hackerone.com",
        auth=("u", "t"),
        headers={"Accept": "application/json"},
    )
    return HackerOneClient(username="u", token="t", client=http)


def test_list_programs_paginates(client):
    programs = client.list_programs()
    handles = [p["attributes"]["handle"] for p in programs]
    assert handles == ["acme", "beta"]


def test_requests_are_authenticated(client):
    client.get_program("acme")
    assert seen_auth and seen_auth[-1].startswith("Basic ")


def test_get_structured_scopes_paginates(client):
    scopes = client.get_structured_scopes("acme")
    idents = [s["attributes"]["asset_identifier"] for s in scopes]
    assert idents == ["api.acme.test", "*.acme.test"]


def test_fetch_program_rules_parses_constraints(client):
    rules = client.fetch_program_rules("acme")
    assert isinstance(rules, ProgramRules)
    assert rules.handle == "acme"
    assert rules.automation_allowed is False  # policy prohibits automated scanning
    assert rules.rate_limit_rps == 3.0
    assert rules.scope_guard_entries() == ["api.acme.test", "*.acme.test"]


def test_from_env_missing_raises():
    with pytest.raises(HackerOneAuthError):
        HackerOneClient.from_env(env={})


def test_constructor_requires_credentials():
    with pytest.raises(HackerOneAuthError):
        HackerOneClient(username="", token="")


def test_map_program_directly():
    rules = map_program(PROGRAM_DETAIL, STRUCTURED_SCOPES_P1["data"] + STRUCTURED_SCOPES_P2["data"])
    assert rules.offers_bounties is True
    assert len(rules.in_scope) == 2


def _client_with(handler, **kwargs) -> HackerOneClient:
    http = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="https://api.hackerone.com",
        auth=("u", "t"),
    )
    kwargs.setdefault("sleep", lambda _d: None)
    return HackerOneClient(username="u", token="t", client=http, **kwargs)


def test_get_retries_on_429_then_succeeds():
    calls = {"n": 0}
    slept: list[float] = []

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"retry-after": "0"}, json={"error": "rate"})
        return httpx.Response(200, json={"data": [{"attributes": {"handle": "acme"}}], "links": {}})

    c = _client_with(handler, sleep=slept.append, max_retries=2)
    programs = c.list_programs()
    assert calls["n"] == 2  # one retry
    assert programs[0]["attributes"]["handle"] == "acme"
    assert slept == [0.0]  # honoured Retry-After: 0


def test_get_raises_after_exhausting_retries():
    def handler(request):
        return httpx.Response(503, json={})

    c = _client_with(handler, max_retries=2)
    with pytest.raises(httpx.HTTPStatusError):
        c.get_program("acme")


def test_non_retryable_status_raises_immediately():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(404, json={})

    c = _client_with(handler, max_retries=3)
    with pytest.raises(httpx.HTTPStatusError):
        c.get_program("x")
    assert calls["n"] == 1  # 404 is not retried


def test_end_to_end_program_to_engine_decision():
    """A mapped (automation-allowed) program -> signed authorization -> the
    engine allows an in-scope wildcard subdomain and denies out-of-scope."""
    now = datetime.now(timezone.utc)
    rules = ProgramRules(
        handle="acme",
        automation_allowed=True,
        in_scope=map_program(PROGRAM_DETAIL, STRUCTURED_SCOPES_P1["data"] + STRUCTURED_SCOPES_P2["data"]).in_scope,
    )
    draft = rules.to_authorization_draft(
        customer_id="cust",
        authorization_id="auth-acme",
        valid_from=(now - timedelta(days=1)).isoformat(),
        valid_until=(now + timedelta(days=30)).isoformat(),
    )
    draft.pop("_meta")  # strip non-authorization metadata before signing

    auth = Authorization(**draft)
    verifier = HmacSignatureVerifier({"kid": "secret"})
    auth.signature = verifier.sign(auth.signing_payload(), "kid")
    auth.signing_key_id = "kid"

    engine = PolicyEngine(authorization=auth, verifier=verifier, audit=lambda _d: None)

    # in-scope subdomain via the wildcard entry
    allow = engine.authorize(ActionRequest(target="shop.acme.test", action="passive_discovery"), now=now)
    assert allow.verdict == Verdict.ALLOW
    # out of scope
    deny = engine.authorize(ActionRequest(target="evil.example.com", action="passive_discovery"), now=now)
    assert deny.verdict == Verdict.DENY
