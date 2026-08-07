"""Draft safe reproduction plans for validated findings.

Static-analysis or AI output is only a candidate until it is reproduced with a deterministic
oracle.  This module models that reproduction intent without executing a live exploit.  The
resulting plan is consumed by Aegis's policy-gated local/authorized executors.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ReproductionPlan:
    """Bounded instructions for validating a candidate in an approved environment."""

    finding_id: str
    environment: str = "local"
    objective: str = "reproduce the reported security property"
    positive_control: str = "execute the minimized candidate request"
    negative_control: str = "repeat without the suspected triggering condition"
    oracle: str = "compare the security-relevant outcome against the negative control"
    request_budget: int = 20
    requires_human_approval: bool = True

    def __post_init__(self) -> None:
        if not self.finding_id.strip():
            raise ValueError("finding_id is required")
        if self.environment not in {"local", "authorized"}:
            raise ValueError("reproduction environment must be local or authorized")
        if self.request_budget <= 0:
            raise ValueError("request_budget must be positive")


def draft_reproduction_plan(
    finding_id: str,
    *,
    environment: str = "local",
    objective: str | None = None,
    request_budget: int = 20,
) -> ReproductionPlan:
    """Return a conservative reproduction plan; no network action is performed here."""
    return ReproductionPlan(
        finding_id=finding_id,
        environment=environment,
        objective=objective or "reproduce the reported security property",
        request_budget=request_budget,
    )
