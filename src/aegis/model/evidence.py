"""Evidence & reproducibility (Master Prompt §7).

A finding is only real if it can be replayed deterministically. Every candidate
must carry an :class:`EvidenceBundle`: the (sanitized) interaction trace,
observed vs. expected behaviour, a canary proving capability, and a reference to
a replay bundle. Proof stops at a canary — never real data.
"""

from __future__ import annotations

import uuid
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class CanaryKind(str, Enum):
    """The minimum non-destructive proof types (§4 invariant 4)."""

    SYNTHETIC_MARKER = "synthetic_marker"
    SEEDED_RECORD = "seeded_record"
    CONTROLLED_EVAL = "controlled_eval"


class Canary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: CanaryKind
    value: str
    note: str = ""


class InteractionStep(BaseModel):
    """One request/response in a replayable sequence. Captures are sanitized."""

    model_config = ConfigDict(extra="forbid")

    summary: str
    request: str | None = None
    response: str | None = None
    sanitized: bool = True


class EvidenceBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    steps: list[InteractionStep] = Field(default_factory=list)
    canary: Canary | None = None
    observed: str = ""
    expected: str = ""
    code_location: str | None = None
    replay_ref: str | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    artifacts: list[str] = Field(default_factory=list)  # screenshot/trace refs

    @property
    def is_reproducible(self) -> bool:
        """Reproducible == has a canary and at least one interaction step.

        Per §7, anything without reproducible evidence is a hypothesis, not a
        finding.
        """
        return self.canary is not None and len(self.steps) > 0

    def request_sequence(self) -> list[str]:
        return [s.summary for s in self.steps]
