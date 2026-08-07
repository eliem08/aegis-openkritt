"""LLM integration (DeepSeek) used strictly as a guardrailed planner (§1, §6).

The model proposes; deterministic filters and the policy gate dispose. See
:class:`LLMPlanner`. Requires ``httpx`` (the ``ai`` / ``api`` / ``dev`` extras).
"""

from .client import DeepSeekClient, DeepSeekCompletion, DeepSeekError
from .code_validation import CodeAnchor, CodeValidation, CodeValidationAgent, ValidationVerdict
from .config import DeepSeekAuthError, DeepSeekConfig, DeepSeekConfigError
from .planner import ALLOWED_ACTIONS, LLMPlanner

__all__ = [
    "ALLOWED_ACTIONS",
    "CodeAnchor",
    "CodeValidation",
    "CodeValidationAgent",
    "DeepSeekAuthError",
    "DeepSeekClient",
    "DeepSeekCompletion",
    "DeepSeekConfig",
    "DeepSeekConfigError",
    "DeepSeekError",
    "LLMPlanner",
    "ValidationVerdict",
]
