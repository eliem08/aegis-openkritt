"""LLM-backed planner with hard deterministic guardrails (Master Prompt §1, §6).

DeepSeek proposes a test plan; this module **filters** that proposal so only
actions that are (a) in the permitted vocabulary and (b) on in-scope targets
survive. Everything else is dropped and counted. This is the concrete
expression of "the LLM is a planner, never the source of truth": even a
hallucinating or prompt-injected model cannot emit a prohibited action or an
out-of-scope target that reaches the policy gate — and the gate re-checks anyway.

If DeepSeek is unavailable (no key, API error, unparseable output), planning
falls back to the deterministic planner, so the system never depends on the LLM.
"""

from __future__ import annotations

import json
import logging
from typing import Protocol

from aegis.model import AttackSurface, EngagementInputs, PlannedAction, TestPlan
from aegis.policy import ScopeGuard
from aegis.policy.consequence import DEFAULT_ACTION_TIERS, ConsequenceTier

from .client import DeepSeekError

logger = logging.getLogger("aegis.ai.planner")

# Actions the model is allowed to propose = every known action that is not
# PROHIBITED. Prohibited actions can never be produced by the planner.
ALLOWED_ACTIONS: frozenset[str] = frozenset(
    a for a, tier in DEFAULT_ACTION_TIERS.items() if tier < ConsequenceTier.PROHIBITED
)

DEFAULT_WORKER_MAP: dict[str, str] = {
    "passive_discovery": "passive_recon",
    "tech_fingerprint": "passive_recon",
    "spec_ingestion": "passive_recon",
}
DEFAULT_WORKER = "probe"

SYSTEM_PROMPT = (
    "You are the planning component of an authorized, scope-limited security "
    "testing agent. Propose a SMALL, bounded set of NON-DESTRUCTIVE test actions. "
    "You must ONLY use actions from the allowed list and ONLY target hosts that are "
    "in scope. Never propose destructive, denial-of-service, data-exfiltration, or "
    "out-of-scope actions. Output STRICT JSON: "
    '{"actions":[{"target":"host","action":"allowed_action","rationale":"why"}]}. '
    "No prose outside the JSON."
)


class _BaseClient(Protocol):
    def complete_json(self, messages: list[dict], **kwargs) -> dict:
        ...


class _FallbackPlanner(Protocol):
    def plan(self, inputs: EngagementInputs, surface: AttackSurface) -> TestPlan:
        ...


class _Knowledge(Protocol):
    def context(self, inputs: EngagementInputs, surface: AttackSurface) -> dict:
        ...


class LLMPlanner:
    def __init__(
        self,
        client: _BaseClient,
        *,
        scope: ScopeGuard | None = None,
        allowed_actions: frozenset[str] | None = None,
        worker_map: dict[str, str] | None = None,
        default_worker: str = DEFAULT_WORKER,
        max_actions: int = 8,
        fallback: _FallbackPlanner | None = None,
        focus_weaknesses: list[str] | None = None,
        knowledge: _Knowledge | None = None,
    ) -> None:
        self._client = client
        self._scope = scope
        self._allowed = allowed_actions or ALLOWED_ACTIONS
        self._worker_map = worker_map or dict(DEFAULT_WORKER_MAP)
        self._default_worker = default_worker
        self._max_actions = max_actions
        self._fallback = fallback
        self._focus = focus_weaknesses or []
        self._knowledge = knowledge  # learned few-shot context (aegis.learn.PlannerKnowledge)
        self.last_dropped: list[dict] = []  # audit of rejected proposals

    def plan(self, inputs: EngagementInputs, surface: AttackSurface) -> TestPlan:
        try:
            data = self._client.complete_json(self._messages(inputs, surface))
            actions = self._guard(data, inputs)
        except (DeepSeekError, Exception) as exc:  # never let the LLM break planning
            logger.warning("LLM planning failed (%s); using fallback", exc)
            return self._fallback_plan(inputs, surface)

        if not actions:
            return self._fallback_plan(inputs, surface)
        return TestPlan(actions=actions)

    def _fallback_plan(self, inputs, surface) -> TestPlan:
        if self._fallback is not None:
            return self._fallback.plan(inputs, surface)
        return TestPlan(actions=[])

    def _scope_for(self, inputs: EngagementInputs) -> ScopeGuard:
        return self._scope if self._scope is not None else ScopeGuard(list(inputs.targets))

    def _guard(self, data, inputs: EngagementInputs) -> list[PlannedAction]:
        self.last_dropped = []
        raw = data.get("actions") if isinstance(data, dict) else data
        if not isinstance(raw, list):
            return []
        scope = self._scope_for(inputs)
        out: list[PlannedAction] = []
        for item in raw[: self._max_actions]:
            if not isinstance(item, dict):
                continue
            action = str(item.get("action", "")).strip()
            target = str(item.get("target", "")).strip()
            if action not in self._allowed:
                self.last_dropped.append({"item": item, "reason": "action_not_allowed"})
                continue
            if not target or not scope.is_allowed(target):
                self.last_dropped.append({"item": item, "reason": "target_out_of_scope"})
                continue
            worker = self._worker_map.get(action, self._default_worker)
            rationale = str(item.get("rationale", ""))[:200]
            out.append(
                PlannedAction(
                    target=target,
                    action=action,
                    worker=worker,
                    rationale=f"[llm] {rationale}".strip(),
                )
            )
        return out

    def _messages(self, inputs: EngagementInputs, surface: AttackSurface) -> list[dict]:
        context = {
            "in_scope_targets": list(inputs.targets),
            "allowed_actions": sorted(self._allowed),
            "known_hosts": sorted(surface.hosts()) if surface else [],
            "notes": inputs.notes,
        }
        if self._focus:
            context["prioritize_weakness_classes"] = self._focus
        if self._knowledge is not None:
            learned = self._knowledge.context(inputs, surface)
            if learned:
                # The LLM conditions on what prior verdicts confirmed vs. rejected.
                context["learned_from_past_outcomes"] = learned
        user = (
            "Plan authorized tests for this engagement. Only in-scope targets, only "
            "allowed actions.\n" + json.dumps(context)
        )
        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
        ]
