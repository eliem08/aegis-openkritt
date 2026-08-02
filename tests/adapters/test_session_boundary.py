"""Cookie/session state stays inside the task boundary (Phase 2 §Katana adapter).

Session material is the most sensitive thing a discovery task holds, so it is
bounded on every axis: one task, in-scope hosts only, never in argv, never in
emitted output, and wiped on close.
"""

from __future__ import annotations

import json

import pytest

from aegis.adapters import EventKind, ExecutionEnvelope, KatanaAdapter
from aegis.adapters.session import REDACTED, SessionBoundary, SessionBoundaryError

STUB = "/opt/aegis/tools/stub"
COOKIE = "session=super-secret-value; Path=/; HttpOnly"


def katana():
    return KatanaAdapter(STUB, allow_unpinned=True)


def envelope(adapter, target="api.example.test", **kw):
    return ExecutionEnvelope.for_manifest(
        adapter.manifest, tenant_id="t", engagement_id="e", scan_id="s", stage_id="st",
        task_id="tk", target=target, scope_digest="d", idempotency_key="k", **kw,
    )


def boundary(task_id="tk", scope_root="api.example.test") -> SessionBoundary:
    return SessionBoundary(task_id=task_id, scope_root=scope_root)


# --- host scoping ------------------------------------------------------------

def test_cookies_are_confined_to_the_host_that_set_them():
    b = boundary(scope_root="example.test")
    b.store("a.example.test", COOKIE)
    assert b.cookies_for("a.example.test") == {"session": "super-secret-value"}
    assert b.cookies_for("b.example.test") == {}      # never offered to a sibling


def test_out_of_scope_hosts_get_and_keep_nothing():
    b = boundary(scope_root="example.test")
    assert b.store("evil.other.test", COOKIE) == 0    # refused on the way in
    assert b.cookies_for("evil.other.test") == {}     # and on the way out


def test_cookie_attributes_are_not_stored_as_cookies():
    b = boundary(scope_root="example.test")
    b.store("a.example.test", COOKIE)
    assert set(b.cookies_for("a.example.test")) == {"session"}  # no Path/HttpOnly


def test_cookie_header_is_rebuilt_only_for_the_owning_host():
    b = boundary(scope_root="example.test")
    b.store("a.example.test", "x=1; y=2")
    assert b.cookie_header("a.example.test") == "x=1; y=2"
    assert b.cookie_header("b.example.test") == ""


# --- task lifetime -----------------------------------------------------------

def test_closing_wipes_state_and_refuses_further_use():
    b = boundary()
    b.store("api.example.test", COOKIE)
    b.close()
    assert b.closed
    with pytest.raises(SessionBoundaryError):
        b.cookies_for("api.example.test")


def test_boundary_works_as_a_context_manager():
    with boundary() as b:
        b.store("api.example.test", COOKIE)
        assert b.cookies_for("api.example.test")
    assert b.closed


def test_two_tasks_never_share_session_state():
    first, second = boundary(task_id="tk-1"), boundary(task_id="tk-2")
    first.store("api.example.test", COOKIE)
    assert second.cookies_for("api.example.test") == {}


# --- never in argv -----------------------------------------------------------

def test_cookies_never_appear_in_the_command_line():
    adapter = katana()
    env = envelope(adapter, credential_refs={"session": "vault://crawl/session"})
    argv = adapter.build_command(env)
    joined = " ".join(argv)
    assert "super-secret-value" not in joined and "vault://" not in joined
    # Only a task-private file path is named.
    assert "-cookie-file" in argv and argv[argv.index("-cookie-file") + 1] == "session-cookies.txt"


def test_no_session_flags_when_the_task_has_no_credentials():
    adapter = katana()
    assert "-cookie-file" not in adapter.build_command(envelope(adapter))


# --- never in output ---------------------------------------------------------

@pytest.mark.parametrize("field", ["cookie", "Set-Cookie", "authorization", "session_id", "token"])
def test_redaction_strips_every_sensitive_field(field):
    clean = SessionBoundary.redact({field: "super-secret-value", "path": "/x"})
    assert clean[field] == REDACTED and clean["path"] == "/x"


def test_redaction_reaches_nested_structures():
    clean = SessionBoundary.redact(
        {"headers": [{"cookie": "a=b"}], "response": {"set-cookie": "c=d", "status": 200}})
    assert clean["headers"][0]["cookie"] == REDACTED
    assert clean["response"]["set-cookie"] == REDACTED and clean["response"]["status"] == 200


def test_crawled_route_never_carries_session_material():
    adapter = katana()
    env = envelope(adapter, credential_refs={"session": "vault://crawl/session"})
    adapter.open_session(env)
    line = json.dumps({
        "request": {"method": "GET", "endpoint": "https://api.example.test/dash",
                    "tag": "a", "source": "https://api.example.test/",
                    "cookie": "session=super-secret-value"},
        "response": {"status_code": 200, "headers": {"set-cookie": COOKIE}},
    })
    event = adapter.parse_line(line, env)
    assert event.kind == EventKind.ROUTE
    assert "super-secret-value" not in json.dumps(event.data)


def test_crawl_keeps_cookies_inside_the_boundary_while_redacting_output():
    adapter = katana()
    env = envelope(adapter, credential_refs={"session": "vault://crawl/session"})
    session = adapter.open_session(env)
    line = json.dumps({
        "request": {"method": "GET", "endpoint": "https://api.example.test/dash", "tag": "a"},
        "response": {"status_code": 200, "headers": {"set-cookie": COOKIE}},
    })
    adapter.parse_line(line, env)
    # Captured for continued crawling of that host...
    assert session.cookies_for("api.example.test") == {"session": "super-secret-value"}
    # ...and gone once the task ends.
    adapter.close_session()
    assert session.closed
