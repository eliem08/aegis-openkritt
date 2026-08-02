"""Planners propose bounded test plans (Master Prompt §3 PLAN).

The planner is where an LLM would sit in a mature system — a *planner and
synthesiser*, never the source of truth. Everything it proposes is gated by the
policy engine before it runs. The implementations here are deterministic so the
loop is testable without a model:

* :class:`StaticPlanner` — replays a fixed list of actions.
* :class:`ReconThenProbePlanner` — emits passive recon for each target, then a
  configurable set of probe actions.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from aegis.model import AttackSurface, EngagementInputs, PlannedAction, TestPlan


@runtime_checkable
class Planner(Protocol):
    def plan(self, inputs: EngagementInputs, surface: AttackSurface) -> TestPlan:
        ...


class StaticPlanner:
    """Returns a fixed plan regardless of inputs (useful for tests/replays)."""

    def __init__(self, actions: list[PlannedAction]) -> None:
        self._actions = list(actions)

    def plan(self, inputs: EngagementInputs, surface: AttackSurface) -> TestPlan:
        return TestPlan(actions=list(self._actions))


class ReconThenProbePlanner:
    """Passive recon per target, then the supplied probe actions.

    ``probe_actions`` are templates; each is retargeted onto every input target.
    """

    def __init__(
        self,
        recon_worker: str = "passive_recon",
        probe_actions: list[PlannedAction] | None = None,
    ) -> None:
        self._recon_worker = recon_worker
        self._probes = list(probe_actions or [])

    def plan(self, inputs: EngagementInputs, surface: AttackSurface) -> TestPlan:
        actions: list[PlannedAction] = []
        for target in inputs.targets:
            actions.append(
                PlannedAction(
                    target=target,
                    action="passive_discovery",
                    worker=self._recon_worker,
                    rationale="map attack surface",
                )
            )
        for target in inputs.targets:
            for probe in self._probes:
                actions.append(probe.model_copy(update={"target": target}))
        return TestPlan(actions=actions)
