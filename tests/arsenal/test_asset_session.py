"""Session guardrails: scope, read-only default, rate limiting, budget, audit log.

No test here touches the network — the transport is a recording double.
"""

import json

import pytest

from aegis.arsenal.assets.scope import OutOfScopeError, build_allowlist
from aegis.arsenal.assets.session import (
    BudgetExhausted,
    HuntSession,
    InteractionRequired,
    RateLimit,
    StateChangeRefused,
    summarize_requests,
)


class RecordingTransport:
    """Stands in for the network; records what would have been sent."""

    def __init__(self, status=200, body=b"ok", headers=None):
        self.calls = []
        self.status = status
        self.body = body
        self.headers = headers or {"Content-Type": "text/plain"}

    def __call__(self, request, timeout):
        self.calls.append({
            "url": request.full_url,
            "method": request.get_method(),
            "headers": dict(request.header_items()),
        })
        return self.status, self.headers, self.body


def make_session(**kwargs):
    transport = kwargs.pop("transport", None) or RecordingTransport()
    slept = []
    session = HuntSession(
        allowlist=kwargs.pop("allowlist", None) or build_allowlist(
            program="acme", in_scope=["*.acme.com"],
        ),
        transport=transport,
        sleep=slept.append,
        **kwargs,
    )
    return session, transport, slept


def test_in_scope_get_is_performed_and_logged():
    session, transport, _ = make_session()
    response = session.get("https://www.acme.com/", technique_id="t1")
    assert response.status_code == 200
    assert len(transport.calls) == 1
    record = session.records[-1]
    assert record.outcome == "completed"
    assert record.host == "www.acme.com"
    assert record.technique_id == "t1"


def test_out_of_scope_request_never_reaches_the_transport():
    session, transport, _ = make_session()
    with pytest.raises(OutOfScopeError):
        session.get("https://evil.com/", technique_id="t1")
    assert transport.calls == []
    assert session.records[-1].outcome == "refused_out_of_scope"


def test_state_changing_method_is_refused_by_default():
    session, transport, _ = make_session()
    with pytest.raises(StateChangeRefused):
        session.request("POST", "https://www.acme.com/", technique_id="t1")
    assert transport.calls == []
    assert session.records[-1].outcome == "refused"


def test_state_change_opt_in_permits_post():
    session, transport, _ = make_session(allow_state_change=True)
    session.request("POST", "https://www.acme.com/", technique_id="t1", body=b"{}")
    assert transport.calls[0]["method"] == "POST"


def test_state_change_opt_in_does_not_relax_scope():
    session, transport, _ = make_session(allow_state_change=True)
    with pytest.raises(OutOfScopeError):
        session.request("POST", "https://evil.com/", technique_id="t1")
    assert transport.calls == []


def test_request_budget_is_enforced():
    session, transport, _ = make_session(rate_limit=RateLimit(max_requests=2))
    session.get("https://a.acme.com/", technique_id="t1")
    session.get("https://b.acme.com/", technique_id="t1")
    with pytest.raises(BudgetExhausted):
        session.get("https://c.acme.com/", technique_id="t1")
    assert len(transport.calls) == 2
    assert session.remaining_budget == 0


def test_rate_limiter_spaces_requests():
    ticks = iter([0.0, 0.0, 0.0, 0.1, 0.1, 0.1, 0.1, 0.1])
    session, _, slept = make_session(rate_limit=RateLimit(requests_per_second=1.0))
    session.clock = lambda: next(ticks)
    session.get("https://a.acme.com/", technique_id="t1")
    session.get("https://b.acme.com/", technique_id="t1")
    assert slept and slept[0] > 0


def test_default_rate_limit_is_conservative():
    limit = RateLimit()
    assert limit.requests_per_second <= 1.0
    assert limit.min_interval >= 1.0


@pytest.mark.parametrize("rps", [0, -1, 25])
def test_absurd_rate_limits_are_rejected(rps):
    with pytest.raises(ValueError):
        RateLimit(requests_per_second=rps)


def test_session_never_injects_credential_headers_on_its_own():
    session, transport, _ = make_session()
    session.get(
        "https://www.acme.com/", technique_id="t1",
        headers={"Authorization": "Bearer smuggled", "X-Trace": "ok"},
    )
    sent = {key.lower() for key in transport.calls[0]["headers"]}
    assert "authorization" not in sent
    assert "x-trace" in sent


def test_operator_supplied_credential_headers_are_honored():
    session, transport, _ = make_session(
        operator_headers={"Authorization": "Bearer operator-chosen"},
    )
    session.get("https://www.acme.com/", technique_id="t1")
    headers = {key.lower(): value for key, value in transport.calls[0]["headers"].items()}
    assert headers["authorization"] == "Bearer operator-chosen"


def test_operator_action_required_stops_the_lane():
    session, transport, _ = make_session()
    with pytest.raises(InteractionRequired) as info:
        session.require_operator_action("t1", "the login form presents a CAPTCHA")
    assert "CAPTCHA" in str(info.value)
    assert transport.calls == []
    assert session.records[-1].outcome == "operator_action_required"


def test_non_http_connections_are_scope_checked_and_audited():
    session, _, _ = make_session()
    host = session.authorize_connection("www.acme.com:443", technique_id="tls", protocol="TLS")
    assert host == "www.acme.com"
    with pytest.raises(OutOfScopeError):
        session.authorize_connection("evil.com:443", technique_id="tls", protocol="TLS")
    assert session.records[-1].outcome == "refused_out_of_scope"


def test_audit_log_is_written_to_disk_as_jsonl(tmp_path):
    log = tmp_path / "requests.jsonl"
    session, _, _ = make_session(log_path=log)
    session.get("https://www.acme.com/", technique_id="t1")
    with pytest.raises(OutOfScopeError):
        session.get("https://evil.com/", technique_id="t1")
    lines = [json.loads(item) for item in log.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 2
    assert lines[0]["outcome"] == "completed"
    assert lines[1]["outcome"] == "refused_out_of_scope"
    assert all("sequence" in item and "observed_at" in item for item in lines)


def test_summarize_requests_rolls_up_outcomes():
    session, _, _ = make_session()
    session.get("https://www.acme.com/", technique_id="t1")
    with pytest.raises(OutOfScopeError):
        session.get("https://evil.com/", technique_id="t1")
    summary = summarize_requests(session.records)
    assert summary["total_attempts"] == 2
    assert summary["outcomes"]["completed"] == 1
    assert summary["hosts_contacted"] == ["www.acme.com"]


def test_transport_errors_are_audited_then_reraised():
    def boom(request, timeout):
        raise OSError("connection reset")

    session, _, _ = make_session(transport=boom)
    with pytest.raises(OSError):
        session.get("https://www.acme.com/", technique_id="t1")
    assert session.records[-1].outcome == "transport_error"
