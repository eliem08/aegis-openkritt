"""The LLM planner conditions its prompt on learned outcomes (in-context learning)."""

from __future__ import annotations

import json

from aegis.ai.planner import LLMPlanner
from aegis.learn import Outcome, OutcomeStore, PlannerKnowledge, Verdict
from aegis.model import AttackSurface, EngagementInputs


class CapturingClient:
    """Records the messages it was asked to complete; returns an empty plan."""
    def __init__(self):
        self.messages = None

    def complete_json(self, messages, **kwargs):
        self.messages = messages
        return {"actions": []}


def _inputs():
    return EngagementInputs(targets=["api.example.test"], notes="")


def test_planner_injects_learned_context_when_feedback_exists():
    store = OutcomeStore()
    store.record(Outcome(detector="analyzer:contract", cwe="CWE-841",
                         verdict=Verdict.CONFIRMED, summary="reentrancy in withdraw was real"))
    store.record(Outcome(detector="analyzer:hardening", cwe="CWE-79",
                         verdict=Verdict.FALSE_POSITIVE, summary="csp warning was noise"))

    client = CapturingClient()
    planner = LLMPlanner(client, knowledge=PlannerKnowledge(store))
    planner.plan(_inputs(), AttackSurface())

    user_msg = next(m["content"] for m in client.messages if m["role"] == "user")
    payload = json.loads(user_msg.split("\n", 1)[1])
    assert "learned_from_past_outcomes" in payload
    learned = payload["learned_from_past_outcomes"]
    assert "reentrancy in withdraw was real" in learned["confirmed_examples"]
    assert "csp warning was noise" in learned["false_positive_examples"]


def test_planner_prompt_unchanged_without_feedback():
    client = CapturingClient()
    planner = LLMPlanner(client, knowledge=PlannerKnowledge(OutcomeStore()))
    planner.plan(_inputs(), AttackSurface())
    user_msg = next(m["content"] for m in client.messages if m["role"] == "user")
    assert "learned_from_past_outcomes" not in user_msg
