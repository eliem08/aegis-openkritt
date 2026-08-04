"""Exploiter + semantic Validator second gate."""

from __future__ import annotations

from aegis.ai.agents.contracts import Hypothesis, VerificationProposal
from aegis.ai.dual_agent import DualAgentReproduction
from aegis.ai.repro_agent import Attempt, ReproPlan, ReproResult


def _hyp():
    return Hypothesis(weakness="CWE-639", title="IDOR", file_path="a.py", line=1,
                      rationale="r", confidence=0.7, entry_point="GET /x",
                      attacker="user", impact="reads another user's data",
                      preconditions="a session", gating="cookie",
                      verification=VerificationProposal(method="response_differential",
                                                        expected_observation="o",
                                                        maximum_requests=2))


def _triggered_result():
    plan = ReproPlan(method="GET", path="/api/session/2", headers={}, body="",
                     rationale="r", success_check="body_contains", success_value="victim@e.com")
    r = ReproResult(triggered=True, summary="reproduced in 1 attempt")
    r.attempts.append(Attempt(plan, 200, True, "oracle satisfied"))
    return r


class _Exploiter:
    def __init__(self, result):
        self._result = result
    def reproduce(self, hyp, target):
        return self._result
    def reproduce_differential(self, hyp, target):
        return self._result


class _Validator:
    def __init__(self, judgement):
        self._j = judgement
    def complete_json(self, messages, **kwargs):
        return self._j


def test_validator_confirms_genuine_impact():
    dual = DualAgentReproduction(
        _Exploiter(_triggered_result()),
        _Validator({"demonstrates_impact": True, "reason": "attacker read victim PII"}))
    result = dual.reproduce(_hyp(), object())
    assert result.triggered is True
    assert "validator confirmed" in result.summary


def test_validator_downgrades_spurious_trigger():
    # deterministic oracle fired, but the marker was just a login page echo
    dual = DualAgentReproduction(
        _Exploiter(_triggered_result()),
        _Validator({"demonstrates_impact": False,
                    "reason": "marker appears on the login page, not as protected data"}))
    result = dual.reproduce(_hyp(), object())
    assert result.triggered is False                       # downgraded
    assert "semantic validator rejected" in result.summary
    assert "validator downgrade" in result.attempts[-1].note


def test_validator_cannot_upgrade_a_miss():
    missed = ReproResult(triggered=False, summary="not reproduced after 3")
    dual = DualAgentReproduction(
        _Exploiter(missed),
        _Validator({"demonstrates_impact": True, "reason": "should not be consulted"}))
    result = dual.reproduce(_hyp(), object())
    assert result.triggered is False                       # unchanged; validator not consulted


def test_invalid_validator_output_fails_closed():
    dual = DualAgentReproduction(_Exploiter(_triggered_result()), _Validator({"garbage": 1}))
    result = dual.reproduce(_hyp(), object())
    assert result.triggered is False                       # no verdict => fail closed
    assert "fail-closed" in result.summary


def test_differential_flag_routes_to_differential_run():
    calls = {"diff": 0, "plain": 0}
    class _E:
        def reproduce(self, h, t): calls["plain"] += 1; return _triggered_result()
        def reproduce_differential(self, h, t): calls["diff"] += 1; return _triggered_result()
    dual = DualAgentReproduction(_E(), _Validator({"demonstrates_impact": True, "reason": "ok"}))
    dual.reproduce(_hyp(), object(), differential=True)
    assert calls == {"diff": 1, "plain": 0}
