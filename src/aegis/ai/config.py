"""Validated DeepSeek configuration for the guardrailed planner."""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-v4-flash"
_THINKING_MODES = frozenset({"enabled", "disabled"})
_REASONING_EFFORTS = frozenset({"low", "high", "max"})


class DeepSeekAuthError(RuntimeError):
    """Raised when the DeepSeek API key is missing."""


class DeepSeekConfigError(ValueError):
    """Raised before network access when DeepSeek configuration is unsafe."""


def _number(env: dict, name: str, default: float) -> float:
    raw = env.get(name)
    if raw in (None, ""):
        return default
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise DeepSeekConfigError(f"{name} must be a number") from exc
    if not math.isfinite(value):
        raise DeepSeekConfigError(f"{name} must be finite")
    return value


def _integer(env: dict, name: str, default: int) -> int:
    raw = env.get(name)
    if raw in (None, ""):
        return default
    try:
        return int(str(raw), 10)
    except (TypeError, ValueError) as exc:
        raise DeepSeekConfigError(f"{name} must be an integer") from exc


@dataclass
class DeepSeekConfig:
    api_key: str
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    connect_timeout: float = 10.0
    read_timeout: float = 60.0
    max_tokens: int = 4096
    temperature: float = 0.2
    thinking: str = "enabled"
    reasoning_effort: str = "high"
    max_retries: int = 3          # transient-error retries (DNS/connect/timeout/429/5xx)
    retry_backoff: float = 0.75   # base seconds for exponential backoff between retries

    def __post_init__(self) -> None:
        self.api_key = str(self.api_key or "").strip()
        self.base_url = str(self.base_url or "").strip().rstrip("/")
        self.model = str(self.model or "").strip()
        self.thinking = str(self.thinking or "").strip().lower()
        self.reasoning_effort = str(self.reasoning_effort or "").strip().lower()

        parsed = urlsplit(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise DeepSeekConfigError("DEEPSEEK_BASE_URL must be an HTTP(S) URL")
        if parsed.username is not None or parsed.password is not None:
            raise DeepSeekConfigError("DEEPSEEK_BASE_URL cannot contain credentials")
        if parsed.query or parsed.fragment:
            raise DeepSeekConfigError("DEEPSEEK_BASE_URL cannot contain a query or fragment")
        if not self.model:
            raise DeepSeekConfigError("DEEPSEEK_MODEL cannot be empty")
        if not math.isfinite(self.connect_timeout) or not 0 < self.connect_timeout <= 120:
            raise DeepSeekConfigError("DEEPSEEK_CONNECT_TIMEOUT must be in (0, 120]")
        if not math.isfinite(self.read_timeout) or not 0 < self.read_timeout <= 600:
            raise DeepSeekConfigError("DEEPSEEK_READ_TIMEOUT must be in (0, 600]")
        if not 1 <= self.max_tokens <= 384_000:
            raise DeepSeekConfigError("DEEPSEEK_MAX_TOKENS must be in [1, 384000]")
        if not math.isfinite(self.temperature) or not 0 <= self.temperature <= 2:
            raise DeepSeekConfigError("DEEPSEEK_TEMPERATURE must be in [0, 2]")
        if self.thinking not in _THINKING_MODES:
            raise DeepSeekConfigError("DEEPSEEK_THINKING must be enabled or disabled")
        if self.reasoning_effort not in _REASONING_EFFORTS:
            raise DeepSeekConfigError("DEEPSEEK_REASONING_EFFORT must be low, high, or max")
        if not 0 <= self.max_retries <= 10:
            raise DeepSeekConfigError("DEEPSEEK_MAX_RETRIES must be in [0, 10]")
        if not math.isfinite(self.retry_backoff) or not 0 <= self.retry_backoff <= 30:
            raise DeepSeekConfigError("DEEPSEEK_RETRY_BACKOFF must be in [0, 30]")

    @property
    def timeout(self) -> httpx.Timeout:
        """Per-operation HTTP timeouts for the direct development client."""
        return httpx.Timeout(
            connect=self.connect_timeout,
            read=self.read_timeout,
            write=self.connect_timeout,
            pool=self.connect_timeout,
        )

    @classmethod
    def from_env(cls, env: dict | None = None) -> "DeepSeekConfig":
        env = env if env is not None else os.environ
        key = str(env.get("DEEPSEEK_API_KEY", "")).strip()
        if not key:
            raise DeepSeekAuthError("set DEEPSEEK_API_KEY in the environment")
        return cls(
            api_key=key,
            base_url=env.get("DEEPSEEK_BASE_URL", DEFAULT_BASE_URL),
            model=env.get("DEEPSEEK_MODEL", DEFAULT_MODEL),
            connect_timeout=_number(env, "DEEPSEEK_CONNECT_TIMEOUT", 10.0),
            read_timeout=_number(env, "DEEPSEEK_READ_TIMEOUT", 60.0),
            max_tokens=_integer(env, "DEEPSEEK_MAX_TOKENS", 4096),
            temperature=_number(env, "DEEPSEEK_TEMPERATURE", 0.2),
            thinking=env.get("DEEPSEEK_THINKING", "enabled"),
            reasoning_effort=env.get("DEEPSEEK_REASONING_EFFORT", "high"),
            max_retries=_integer(env, "DEEPSEEK_MAX_RETRIES", 3),
            retry_backoff=_number(env, "DEEPSEEK_RETRY_BACKOFF", 0.75),
        )

    @classmethod
    def maybe_from_env(cls, env: dict | None = None) -> "DeepSeekConfig | None":
        """Return a config if a key is set, else None (enables graceful fallback)."""
        try:
            return cls.from_env(env)
        except DeepSeekAuthError:
            return None
