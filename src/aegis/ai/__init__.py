"""LLM integration (DeepSeek) used strictly as a guardrailed planner (§1, §6).

The model proposes; deterministic filters and the policy gate dispose. See
:class:`LLMPlanner`. Requires ``httpx`` (the ``ai`` / ``api`` / ``dev`` extras).
"""

from .client import DeepSeekClient, DeepSeekError
from .config import DeepSeekAuthError, DeepSeekConfig
from .planner import ALLOWED_ACTIONS, LLMPlanner

__all__ = [
    "DeepSeekClient",
    "DeepSeekError",
    "DeepSeekConfig",
    "DeepSeekAuthError",
    "LLMPlanner",
    "ALLOWED_ACTIONS",
]
