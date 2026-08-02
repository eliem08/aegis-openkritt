"""The safety-critical tests: the LLM cannot smuggle out-of-scope or prohibited
actions past the guardrails, and planning never depends on the LLM."""

from aegis.ai import LLMPlanner
from aegis.ai.client import DeepSeekError
from aegis.model import EngagementInputs
from aegis.orchestrator import StaticPlanner
from aegis.policy import ScopeGuard

INPUTS = EngagementInputs(targets=["api.example.test", "*.example.test"])
SCOPE = ScopeGuard(["api.example.test", "*.example.test"])


class FakeClient:
    def __init__(self, data):
        self._data = data

    def complete_json(self, messages, **kwargs):
        if isinstance(self._data, Exception):
            raise self._data
        return self._data


def test_valid_actions_survive():
    data = {"actions": [
        {"target": "api.example.test", "action": "passive_discovery", "rationale": "map"},
        {"target": "shop.example.test", "action": "authenticated_testing", "rationale": "authz"},
    ]}
    plan = LLMPlanner(FakeClient(data), scope=SCOPE).plan(INPUTS, None)
    assert [a.action for a in plan.actions] == ["passive_discovery", "authenticated_testing"]
    assert plan.actions[0].worker == "passive_recon"
    assert plan.actions[0].rationale.startswith("[llm]")


def test_out_of_scope_target_dropped():
    data = {"actions": [
        {"target": "evil.com", "action": "passive_discovery"},
        {"target": "api.example.test", "action": "passive_discovery"},
    ]}
    p = LLMPlanner(FakeClient(data), scope=SCOPE)
    plan = p.plan(INPUTS, None)
    assert len(plan.actions) == 1
    assert plan.actions[0].target == "api.example.test"
    assert any(d["reason"] == "target_out_of_scope" for d in p.last_dropped)


def test_prohibited_or_unknown_action_dropped():
    data = {"actions": [
        {"target": "api.example.test", "action": "denial_of_service"},  # prohibited
        {"target": "api.example.test", "action": "rm_rf_everything"},   # unknown
        {"target": "api.example.test", "action": "passive_discovery"},  # ok
    ]}
    p = LLMPlanner(FakeClient(data), scope=SCOPE)
    plan = p.plan(INPUTS, None)
    assert [a.action for a in plan.actions] == ["passive_discovery"]
    assert sum(d["reason"] == "action_not_allowed" for d in p.last_dropped) == 2


def test_max_actions_capped():
    data = {"actions": [{"target": "api.example.test", "action": "passive_discovery"}] * 20}
    plan = LLMPlanner(FakeClient(data), scope=SCOPE, max_actions=3).plan(INPUTS, None)
    assert len(plan.actions) == 3


def test_falls_back_when_llm_errors():
    fallback = StaticPlanner([
        __import__("aegis.model", fromlist=["PlannedAction"]).PlannedAction(
            target="api.example.test", action="passive_discovery", worker="passive_recon"
        )
    ])
    plan = LLMPlanner(FakeClient(DeepSeekError("boom")), scope=SCOPE, fallback=fallback).plan(INPUTS, None)
    assert len(plan.actions) == 1  # from the fallback


def test_falls_back_when_no_valid_actions():
    from aegis.model import PlannedAction

    fallback = StaticPlanner([PlannedAction(target="api.example.test", action="passive_discovery", worker="passive_recon")])
    data = {"actions": [{"target": "evil.com", "action": "denial_of_service"}]}  # all rejected
    plan = LLMPlanner(FakeClient(data), scope=SCOPE, fallback=fallback).plan(INPUTS, None)
    assert len(plan.actions) == 1
    assert plan.actions[0].target == "api.example.test"


def test_garbage_response_yields_empty_without_fallback():
    plan = LLMPlanner(FakeClient({"unexpected": True}), scope=SCOPE).plan(INPUTS, None)
    assert plan.actions == []
