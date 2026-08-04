"""Bounded, oracle-verified reproduction agent."""

from __future__ import annotations

import pytest

from aegis.ai.agents.contracts import Hypothesis, VerificationProposal
from aegis.ai.repro_agent import (
    Attempt, ReproductionAgent, ReproError, ReproPlan, ReproTarget, ResponseView,
    evaluate_oracle, is_local_target,
)


def _hyp():
    return Hypothesis(
        weakness="CWE-639", title="IDOR", file_path="a.py", line=1,
        rationale="lookup by client id without ownership check",
        confidence=0.7, entry_point="GET /api/session/{id}",
        attacker="any user", impact="reads another user's data",
        preconditions="a valid low-priv session", gating="cookie session",
        verification=VerificationProposal(method="response_differential",
                                          expected_observation="other user's data returned",
                                          maximum_requests=3),
    )


def _plan(**over):
    base = dict(method="GET", path="/api/session/2", headers={}, body="",
                rationale="request another user's session by id",
                success_check="body_contains", success_value="victim@example.com")
    base.update(over)
    return base


class _Client:
    def __init__(self, plans):
        self._plans = list(plans)
        self.prompts = []

    def complete_json(self, messages, **kwargs):
        self.prompts.append(messages[1]["content"])
        return self._plans.pop(0) if self._plans else {}


class _Executor:
    def __init__(self, responses):
        self._responses = list(responses)
        self.sent = []

    def send(self, target, plan):
        self.sent.append((target, plan))
        return self._responses.pop(0)


# --- safety rails -----------------------------------------------------------

def test_local_target_detection():
    for ok in ["http://127.0.0.1:8080", "http://localhost:3000", "http://app.localhost",
               "http://10.0.0.5", "http://192.168.1.9:80"]:
        assert is_local_target(ok), ok
    for bad in ["https://matomo.org", "http://8.8.8.8", "https://api.github.com", ""]:
        assert not is_local_target(bad), bad


def test_refuses_non_local_target():
    agent = ReproductionAgent(_Client([]), _Executor([]))
    with pytest.raises(ReproError, match="non-local"):
        agent.reproduce(_hyp(), ReproTarget(base_url="https://matomo.org"))


def test_destructive_method_blocked_by_default():
    client = _Client([_plan(method="DELETE", path="/api/user/2")])
    ex = _Executor([])                                    # should never be reached
    result = ReproductionAgent(client, ex).reproduce(_hyp(), ReproTarget("http://127.0.0.1:8080"))
    assert result.triggered is False
    assert ex.sent == []                                   # request never sent
    assert "destructive method blocked" in result.attempts[-1].note


def test_destructive_method_allowed_when_opted_in():
    client = _Client([_plan(method="DELETE", success_check="status_equals", success_value="200")])
    ex = _Executor([ResponseView(status=200, text="")])
    result = ReproductionAgent(client, ex).reproduce(
        _hyp(), ReproTarget("http://127.0.0.1:8080", allow_destructive=True))
    assert ex.sent and result.triggered is True


# --- oracle -----------------------------------------------------------------

def test_oracle_checks():
    assert evaluate_oracle(ReproPlan(**_plan(success_check="status_equals", success_value="200")),
                           ResponseView(200, "")) is True
    assert evaluate_oracle(ReproPlan(**_plan(success_check="status_in", success_value="200,201")),
                           ResponseView(201, "")) is True
    assert evaluate_oracle(ReproPlan(**_plan(success_check="body_contains", success_value="secret")),
                           ResponseView(200, "here is a secret")) is True
    assert evaluate_oracle(ReproPlan(**_plan(success_check="body_absent", success_value="denied")),
                           ResponseView(200, "welcome")) is True
    assert evaluate_oracle(ReproPlan(**_plan(success_check="body_contains", success_value="x")),
                           ResponseView(200, "nope")) is False


# --- the loop ---------------------------------------------------------------

def test_reproduces_when_oracle_satisfied():
    client = _Client([_plan()])
    ex = _Executor([ResponseView(200, "email: victim@example.com")])
    result = ReproductionAgent(client, ex).reproduce(_hyp(), ReproTarget("http://127.0.0.1:8080"))
    assert result.triggered is True and result.verdict == "reproduced"
    assert len(result.attempts) == 1 and result.attempts[0].triggered


def test_refines_across_attempts_with_feedback():
    # first attempt misses; second, informed by the response, hits
    client = _Client([_plan(path="/api/session/1"), _plan(path="/api/session/2")])
    ex = _Executor([ResponseView(403, "forbidden"),
                    ResponseView(200, "email: victim@example.com")])
    agent = ReproductionAgent(client, ex, max_attempts=4)
    result = agent.reproduce(_hyp(), ReproTarget("http://127.0.0.1:8080"))
    assert result.triggered is True
    assert len(result.attempts) == 2
    # the second prompt carried feedback from the first response
    assert "403" in client.prompts[1] and "forbidden" in client.prompts[1]


def test_gives_up_within_budget():
    client = _Client([_plan(), _plan(), _plan(), _plan(), _plan()])
    ex = _Executor([ResponseView(403, "no") for _ in range(5)])
    result = ReproductionAgent(client, ex, max_attempts=3).reproduce(
        _hyp(), ReproTarget("http://127.0.0.1:8080"))
    assert result.triggered is False
    assert len(result.attempts) == 3                       # budget respected
    assert "not reproduced" in result.summary


def test_invalid_plan_stops_cleanly():
    client = _Client([{"garbage": True}])
    result = ReproductionAgent(client, _Executor([])).reproduce(
        _hyp(), ReproTarget("http://127.0.0.1:8080"))
    assert result.triggered is False
    assert "did not return a valid ReproPlan" in result.summary


# --- differential oracle (IDOR / access control) ----------------------------

from aegis.ai.repro_agent import DifferentialTarget   # noqa: E402


class _DiffExecutor:
    """Returns responses keyed by which auth header is presented."""
    def __init__(self, by_auth):
        self._by_auth = by_auth
        self.sent = []

    def send(self, target, plan):
        self.sent.append((target.auth_header, plan))
        return self._by_auth[target.auth_header]


def test_differential_confirms_when_attacker_sees_victim_marker():
    client = _Client([_plan(path="/api/session/1", success_value="victim@example.com")])
    ex = _DiffExecutor({
        "Bearer VICTIM": ResponseView(200, "owner email: victim@example.com"),
        "Bearer ATTACKER": ResponseView(200, "owner email: victim@example.com"),  # bypass!
    })
    agent = ReproductionAgent(client, ex)
    result = agent.reproduce_differential(
        _hyp(), DifferentialTarget("http://127.0.0.1:8080", "Bearer VICTIM", "Bearer ATTACKER"))
    assert result.triggered is True
    assert "bypass" in result.attempts[-1].note


def test_differential_negative_when_access_control_holds():
    client = _Client([_plan(success_value="victim@example.com"),
                      _plan(success_value="victim@example.com")])
    ex = _DiffExecutor({
        "Bearer VICTIM": ResponseView(200, "owner email: victim@example.com"),
        "Bearer ATTACKER": ResponseView(403, "forbidden"),   # control holds
    })
    agent = ReproductionAgent(client, ex, max_attempts=2)
    result = agent.reproduce_differential(
        _hyp(), DifferentialTarget("http://127.0.0.1:8080", "Bearer VICTIM", "Bearer ATTACKER"))
    assert result.triggered is False


def test_differential_rejects_wrong_marker_not_in_victim():
    # if the marker isn't even in the victim's response, it's not the victim's data
    client = _Client([_plan(success_value="not-real-data")])
    ex = _DiffExecutor({
        "Bearer VICTIM": ResponseView(200, "owner email: victim@example.com"),
        "Bearer ATTACKER": ResponseView(200, "not-real-data everywhere"),
    })
    agent = ReproductionAgent(client, ex, max_attempts=1)
    result = agent.reproduce_differential(
        _hyp(), DifferentialTarget("http://127.0.0.1:8080", "Bearer VICTIM", "Bearer ATTACKER"))
    assert result.triggered is False                     # marker not in victim => not proof


def test_differential_refuses_non_local():
    agent = ReproductionAgent(_Client([]), _DiffExecutor({}))
    with pytest.raises(ReproError, match="non-local"):
        agent.reproduce_differential(_hyp(), DifferentialTarget("https://prod.example.com", "v", "a"))
