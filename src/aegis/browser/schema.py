"""Declarative browser-workflow schema (Phase 4 §Browser worker).

Workflows are data, not code. The initial step vocabulary is navigation, element
assertions, form fill, click, wait-for-condition, response capture, and synthetic
canary checks — and nothing else: arbitrary JavaScript is forbidden by default, so
a script/eval step is rejected unless a workflow is *explicitly* marked to allow
it (which the worker further requires be authorized). Form fills carry credential
*references*, never raw secrets — a literal that classifies as sensitive is
refused before anything runs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from aegis.sensitive import SensitiveDataClassifier

# Capabilities that are always off in an Aegis browser context.
DISABLED_CAPABILITIES = (
    "clipboard", "filesystem", "camera", "microphone", "geolocation",
    "extensions", "debug_port", "usb", "midi",
)


class StepType(str, Enum):
    NAVIGATE = "navigate"
    ASSERT_ELEMENT = "assert_element"
    FILL = "fill"
    CLICK = "click"
    WAIT_FOR = "wait_for"
    CAPTURE = "capture_response"
    CANARY_CHECK = "canary_check"


# Anything that would run arbitrary script is not part of the schema.
FORBIDDEN_STEP_NAMES = frozenset({"eval", "script", "evaluate", "exec", "inject", "add_script"})


class WorkflowError(ValueError):
    pass


@dataclass(frozen=True)
class WorkflowStep:
    type: StepType
    params: dict = field(default_factory=dict)


@dataclass(frozen=True)
class BrowserWorkflow:
    steps: tuple[WorkflowStep, ...]
    identity: str                       # the owned identity this workflow runs as
    allow_javascript: bool = False      # must ALSO be authorized at run time
    intends_logout: bool = False        # only then may a logout path be visited

    def validate(self, classifier: SensitiveDataClassifier | None = None) -> None:
        clf = classifier or SensitiveDataClassifier()
        if not self.identity:
            raise WorkflowError("a workflow must declare the owned identity it runs as")
        for step in self.steps:
            if not isinstance(step.type, StepType):
                raise WorkflowError(f"unknown step type {step.type!r}")
            if step.type.value in FORBIDDEN_STEP_NAMES and not self.allow_javascript:
                raise WorkflowError("arbitrary JavaScript is forbidden by default")
            if step.type == StepType.NAVIGATE and not step.params.get("url"):
                raise WorkflowError("navigate step requires a url")
            if step.type == StepType.FILL:
                _validate_fill(step, clf)


def _validate_fill(step: WorkflowStep, clf: SensitiveDataClassifier) -> None:
    ref = step.params.get("credential_ref")
    value = step.params.get("value")
    if ref:
        if not str(ref).startswith(("vault://", "ref://", "env://")):
            raise WorkflowError("credential_ref must be a reference, not a value")
        return
    if value is not None and clf.classify(str(value)).sensitive:
        # A raw secret pasted into the workflow is refused; use credential_ref.
        raise WorkflowError("fill value looks sensitive; use a credential_ref")


def parse_workflow(data: dict) -> BrowserWorkflow:
    """Build a workflow from a declarative dict (e.g. loaded from YAML/JSON)."""
    steps = []
    for raw in data.get("steps", []):
        try:
            step_type = StepType(raw["type"])
        except (KeyError, ValueError) as exc:
            raise WorkflowError(f"invalid step: {raw!r}") from exc
        steps.append(WorkflowStep(step_type, dict(raw.get("params", {}))))
    return BrowserWorkflow(
        steps=tuple(steps), identity=data.get("identity", ""),
        allow_javascript=bool(data.get("allow_javascript", False)),
        intends_logout=bool(data.get("intends_logout", False)))
