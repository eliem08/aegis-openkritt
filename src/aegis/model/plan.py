"""Test plan and planned actions (Master Prompt §3 PLAN).

A ``PlannedAction`` is the unit the orchestrator gates: it names the target, the
action class (which maps to a consequence tier), and the worker that would carry
it out. The planner proposes; the policy engine disposes.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict, Field

from aegis.policy import ConsequenceTier


class PlannedAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    target: str
    action: str
    worker: str
    tier_hint: ConsequenceTier | None = None
    rationale: str = ""
    params: dict = Field(default_factory=dict)
    estimated_cost: float = 0.0
    touches_production: bool = False


class TestPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actions: list[PlannedAction] = Field(default_factory=list)

    def __len__(self) -> int:
        return len(self.actions)


class EngagementInputs(BaseModel):
    """What the planner is given to work from (§3 INGEST)."""

    model_config = ConfigDict(extra="forbid")

    targets: list[str] = Field(default_factory=list)
    notes: str = ""
    seeds: dict = Field(default_factory=dict)
