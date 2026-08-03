"""Configuration loader for the hardened Compose deployment.

Secret-bearing values use ``*_FILE`` inputs. The loader materializes them only
in a private mapping passed to the existing control-plane configuration; it does
not mutate the process environment or print values.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from aegis.api.config import ControlPlaneConfig, _flag

SECRET_ENV_KEYS = frozenset({
    "AEGIS_API_KEYS",
    "AEGIS_SIGNING_KEYS",
    "AEGIS_ENCRYPTION_KEY",
    "AEGIS_DB_URL",
    "AEGIS_REDIS_URL",
    "AEGIS_OPENKRITT_API_KEY",
    "AEGIS_MODEL_GATEWAY_TOKEN",
})


class SecretConfigurationError(ValueError):
    pass


def _read_secret_file(path_text: str, *, name: str) -> str:
    path = Path(path_text)
    if not path.is_file():
        raise SecretConfigurationError(f"{name}_FILE does not name a readable file")
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise SecretConfigurationError(f"{name}_FILE is empty")
    return value


def materialize_secret_environment(
    env: Mapping[str, str],
) -> tuple[dict[str, str], dict[str, str]]:
    """Return a private env copy and secret-source metadata.

    Supplying both a value and its ``_FILE`` form is rejected because precedence
    ambiguity can cause an operator to rotate the wrong credential.
    """
    result = dict(env)
    sources: dict[str, str] = {}
    for name in SECRET_ENV_KEYS:
        file_name = f"{name}_FILE"
        direct = result.get(name)
        file_path = result.get(file_name)
        if direct and file_path:
            raise SecretConfigurationError(f"configure only one of {name} and {file_name}")
        if file_path:
            result[name] = _read_secret_file(file_path, name=name)
            sources[name] = "file"
        elif direct:
            sources[name] = "environment"
    return result, sources


@dataclass(frozen=True)
class ProductionSettings:
    control: ControlPlaneConfig
    redis_url: str | None
    namespace: str
    oast_domain: str | None
    egress_enforced: bool
    egress_url: str | None
    browser_image: str | None
    scanner_lock_path: str | None
    model_gateway_url: str | None = None
    model_gateway_token: str | None = None
    require_model_gateway: bool = False
    require_oast: bool = True
    secret_sources: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "ProductionSettings":
        source = os.environ if env is None else env
        materialized, secret_sources = materialize_secret_environment(source)
        if not _flag(materialized.get("AEGIS_PRODUCTION"), default=False):
            raise SecretConfigurationError("AEGIS_PRODUCTION=1 is required")
        namespace = materialized.get("AEGIS_COORD_NAMESPACE", "aegis-prod").strip(" :")
        if not namespace:
            raise SecretConfigurationError("AEGIS_COORD_NAMESPACE must not be empty")
        return cls(
            control=ControlPlaneConfig.from_env(materialized),
            redis_url=materialized.get("AEGIS_REDIS_URL") or None,
            namespace=namespace,
            oast_domain=materialized.get("AEGIS_OAST_DOMAIN") or None,
            egress_enforced=_flag(materialized.get("AEGIS_EGRESS_ENFORCED"), default=False),
            egress_url=materialized.get("AEGIS_EGRESS_URL") or None,
            browser_image=materialized.get("AEGIS_BROWSER_IMAGE") or None,
            scanner_lock_path=materialized.get("AEGIS_SCANNER_LOCK") or None,
            model_gateway_url=materialized.get("AEGIS_MODEL_GATEWAY_URL") or None,
            model_gateway_token=materialized.get("AEGIS_MODEL_GATEWAY_TOKEN") or None,
            require_model_gateway=_flag(
                materialized.get("AEGIS_REQUIRE_MODEL_GATEWAY"), default=False,
            ),
            require_oast=_flag(materialized.get("AEGIS_REQUIRE_OAST"), default=True),
            secret_sources=secret_sources,
        )

    def build_coordinator(self):
        if not self.redis_url:
            raise SecretConfigurationError("AEGIS_REDIS_URL_FILE is required")
        from aegis.coord.redis_backend import RedisBackend, RedisCoordinator

        backend = RedisBackend(self.redis_url, namespace=self.namespace)
        return RedisCoordinator(backend)
