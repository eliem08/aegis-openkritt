"""DeepSeek configuration (the LLM used as planner/synthesiser, §1).

The model is a *planner and synthesiser, never the source of truth*. Its API key
is read from the environment (``DEEPSEEK_API_KEY``) and never logged. DeepSeek's
API is OpenAI-compatible, so the client speaks the ``/chat/completions`` shape.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-chat"  # or "deepseek-reasoner"


class DeepSeekAuthError(RuntimeError):
    """Raised when the DeepSeek API key is missing."""


@dataclass
class DeepSeekConfig:
    api_key: str
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    timeout: float = 60.0
    temperature: float = 0.2
    max_tokens: int = 1024

    @classmethod
    def from_env(cls, env: dict | None = None) -> "DeepSeekConfig":
        env = env if env is not None else os.environ
        key = env.get("DEEPSEEK_API_KEY", "")
        if not key:
            raise DeepSeekAuthError("set DEEPSEEK_API_KEY in the environment")
        return cls(
            api_key=key,
            base_url=env.get("DEEPSEEK_BASE_URL", DEFAULT_BASE_URL),
            model=env.get("DEEPSEEK_MODEL", DEFAULT_MODEL),
        )

    @classmethod
    def maybe_from_env(cls, env: dict | None = None) -> "DeepSeekConfig | None":
        """Return a config if a key is set, else None (enables graceful fallback)."""
        try:
            return cls.from_env(env)
        except DeepSeekAuthError:
            return None
