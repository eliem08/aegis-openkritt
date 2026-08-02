"""Guarded browser workflows (Phase 4).

Declarative workflows run through a pinned Chromium driver behind the scoped
execution gateway: no arbitrary JS, every request scope-checked, downloads
quarantined, capabilities disabled, and ephemeral per-tenant/identity contexts.
"""

from .schema import (
    DISABLED_CAPABILITIES,
    FORBIDDEN_STEP_NAMES,
    BrowserWorkflow,
    StepType,
    WorkflowError,
    WorkflowStep,
    parse_workflow,
)
from .worker import (
    DEFAULT_LOGOUT_PATHS,
    BrowserDriver,
    BrowserWorker,
    EphemeralContext,
    PageResult,
    WorkflowResult,
)

__all__ = [
    "BrowserWorkflow",
    "WorkflowStep",
    "StepType",
    "WorkflowError",
    "parse_workflow",
    "DISABLED_CAPABILITIES",
    "FORBIDDEN_STEP_NAMES",
    "BrowserWorker",
    "BrowserDriver",
    "EphemeralContext",
    "PageResult",
    "WorkflowResult",
    "DEFAULT_LOGOUT_PATHS",
]
