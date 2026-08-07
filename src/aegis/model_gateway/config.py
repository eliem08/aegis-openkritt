"""Fail-closed configuration for the dedicated DeepSeek gateway."""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


class ModelGatewayConfigError(ValueError):
    """Unsafe or incomplete gateway configuration."""


def _secret(source: dict, file_name: str, direct_name: str) -> str:
    file_value = str(source.get(file_name, "")).strip()
    direct_value = str(source.get(direct_name, "")).strip()
    if file_value and direct_value:
        raise ModelGatewayConfigError(f"set only one of {file_name} and {direct_name}")
    if file_value:
        try:
            value = Path(file_value).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ModelGatewayConfigError(f"cannot read {file_name}") from exc
    else:
        value = direct_value
    if not value:
        raise ModelGatewayConfigError(f"missing {file_name}")
    return value


def _optional_secret(source: dict, file_name: str, direct_name: str) -> str | None:
    if not str(source.get(file_name, "")).strip() and not str(source.get(direct_name, "")).strip():
        return None
    return _secret(source, file_name, direct_name)


def _float(source: dict, name: str, default: float, low: float, high: float) -> float:
    try:
        value = float(source.get(name, default))
    except (TypeError, ValueError) as exc:
        raise ModelGatewayConfigError(f"{name} must be numeric") from exc
    if not math.isfinite(value) or not low <= value <= high:
        raise ModelGatewayConfigError(f"{name} must be in [{low}, {high}]")
    return value


@dataclass(frozen=True)
class ModelGatewayConfig:
    provider_api_key: str
    caller_token: str
    provider_origin: str = "https://api.deepseek.com"
    connect_timeout: float = 10.0
    read_timeout: float = 120.0
    max_attempts: int = 3
    circuit_failures: int = 5
    circuit_cooldown: float = 30.0
    cache_ttl: float = 300.0
    redis_url: str | None = None
    database_url: str | None = None
    budget_namespace: str = "aegis-prod:model-cost"
    require_durable_budget: bool = False

    def __post_init__(self) -> None:
        origin = self.provider_origin.rstrip("/")
        parsed = urlsplit(origin)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
        ):
            raise ModelGatewayConfigError("provider origin must be an HTTPS origin without credentials")
        if len(self.provider_api_key) < 8:
            raise ModelGatewayConfigError("provider API key is too short")
        if len(self.caller_token) < 32:
            raise ModelGatewayConfigError("gateway caller token is too short")
        if not 1 <= self.max_attempts <= 5:
            raise ModelGatewayConfigError("max attempts must be in [1, 5]")
        if not 1 <= self.circuit_failures <= 100:
            raise ModelGatewayConfigError("circuit failures must be in [1, 100]")
        if self.require_durable_budget and (not self.redis_url or not self.database_url):
            raise ModelGatewayConfigError(
                "production model gateway requires Redis and PostgreSQL ledgers"
            )
        if self.redis_url:
            redis = urlsplit(self.redis_url)
            if redis.scheme not in {"redis", "rediss"} or not redis.hostname or not redis.password:
                raise ModelGatewayConfigError("Redis URL must be authenticated redis:// or rediss://")
        if self.database_url:
            database = urlsplit(self.database_url)
            query = parse_qs(database.query)
            if (
                database.scheme not in {"postgres", "postgresql"}
                or not database.hostname
                or not database.password
                or query.get("sslmode") != ["verify-full"]
            ):
                raise ModelGatewayConfigError(
                    "PostgreSQL URL must be authenticated with sslmode=verify-full"
                )
        if not self.budget_namespace.strip(" :"):
            raise ModelGatewayConfigError("budget namespace cannot be empty")
        object.__setattr__(self, "provider_origin", origin)

    @classmethod
    def from_env(cls, env: dict | None = None) -> ModelGatewayConfig:
        source = os.environ if env is None else env
        try:
            attempts = int(source.get("AEGIS_MODEL_MAX_ATTEMPTS", "3"))
            failures = int(source.get("AEGIS_MODEL_CIRCUIT_FAILURES", "5"))
        except (TypeError, ValueError) as exc:
            raise ModelGatewayConfigError("attempt and circuit settings must be integers") from exc
        return cls(
            provider_api_key=_secret(
                source, "AEGIS_MODEL_PROVIDER_KEY_FILE", "AEGIS_MODEL_PROVIDER_KEY",
            ),
            caller_token=_secret(
                source, "AEGIS_MODEL_GATEWAY_TOKEN_FILE", "AEGIS_MODEL_GATEWAY_TOKEN",
            ),
            provider_origin=str(
                source.get("AEGIS_MODEL_PROVIDER_ORIGIN", "https://api.deepseek.com")
            ),
            connect_timeout=_float(
                source, "AEGIS_MODEL_CONNECT_TIMEOUT", 10.0, 0.1, 120.0,
            ),
            read_timeout=_float(
                source, "AEGIS_MODEL_READ_TIMEOUT", 120.0, 0.1, 600.0,
            ),
            max_attempts=attempts,
            circuit_failures=failures,
            circuit_cooldown=_float(
                source, "AEGIS_MODEL_CIRCUIT_COOLDOWN", 30.0, 1.0, 3600.0,
            ),
            cache_ttl=_float(source, "AEGIS_MODEL_CACHE_TTL", 300.0, 0.0, 86400.0),
            redis_url=_optional_secret(
                source, "AEGIS_REDIS_URL_FILE", "AEGIS_REDIS_URL",
            ),
            database_url=_optional_secret(
                source, "AEGIS_DB_URL_FILE", "AEGIS_DB_URL",
            ),
            budget_namespace=str(
                source.get("AEGIS_MODEL_BUDGET_NAMESPACE", "aegis-prod:model-cost")
            ),
            require_durable_budget=str(source.get("AEGIS_PRODUCTION", "")).lower()
            in {"1", "true", "yes"},
        )
