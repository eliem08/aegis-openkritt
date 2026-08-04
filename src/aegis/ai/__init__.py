"""LLM integration (DeepSeek) used strictly as a guardrailed planner (§1, §6).

The model proposes; deterministic filters and the policy gate dispose. See
:class:`LLMPlanner`. Requires ``httpx`` (the ``ai`` / ``api`` / ``dev`` extras).
"""

from .client import DeepSeekClient, DeepSeekCompletion, DeepSeekError
from .config import DeepSeekAuthError, DeepSeekConfig, DeepSeekConfigError
from .code_validation import CodeAnchor, CodeValidation, CodeValidationAgent, ValidationVerdict
from .planner import ALLOWED_ACTIONS, LLMPlanner

__all__ = [
    "DeepSeekClient",
    "DeepSeekCompletion",
    "DeepSeekError",
    "DeepSeekConfig",
    "DeepSeekAuthError",
    "DeepSeekConfigError",
    "CodeAnchor",
    "CodeValidation",
    "CodeValidationAgent",
    "ValidationVerdict",
    "LLMPlanner",
    "ALLOWED_ACTIONS",
]
