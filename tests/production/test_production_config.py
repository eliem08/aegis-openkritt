from __future__ import annotations

import json

import pytest

from aegis.api.prodcheck import ProductionReadinessError
from aegis.production import (
    ProductionSettings,
    SecretConfigurationError,
    production_deployment_issues,
    require_production_deployment,
)

PIN = "a" * 64
IMAGE = f"registry.example/aegis/browser@sha256:{PIN}"


def secret(tmp_path, name, value):
    path = tmp_path / name
    path.write_text(value, encoding="utf-8")
    return str(path)


def environment(tmp_path):
    lock = tmp_path / "scanners.lock.json"
    lock.write_text(json.dumps({"releases": [{
        "name": "scanner", "version": "1", "sha256": PIN,
        "image": f"registry.example/scanner@sha256:{PIN}",
        "license_reviewed": True, "output_schema": "aegis.v1",
    }]}), encoding="utf-8")
    return {
        "AEGIS_PRODUCTION": "1",
        "AEGIS_API_KEYS_FILE": secret(tmp_path, "api", json.dumps({
            "token": {"role": "operator", "tenant": "tenant-a"},
        })),
        "AEGIS_ED25519_PUBLIC_KEYS": json.dumps({"kid": "ab" * 32}),
        "AEGIS_ENCRYPTION_KEY_FILE": secret(tmp_path, "enc", "encryption-key"),
        "AEGIS_DB_URL_FILE": secret(
            tmp_path, "db", "postgresql://svc_aegis:strong-pass@pg.prod.internal/aegis?sslmode=require",
        ),
        "AEGIS_REDIS_URL_FILE": secret(
            tmp_path, "redis", "redis://default:strong-pass@redis.prod.internal:6379/0",
        ),
        "AEGIS_LEARN_DB": str(tmp_path / "learn.db"),
        "AEGIS_EGRESS_ENFORCED": "1",
        "AEGIS_EGRESS_URL": "http://egress.prod.internal:8080",
        "AEGIS_BROWSER_IMAGE": IMAGE,
        "AEGIS_SCANNER_LOCK": str(lock),
        "AEGIS_OAST_DOMAIN": "oast.prod.internal",
    }


def codes(settings):
    return {issue.code for issue in production_deployment_issues(settings)}


def test_production_flag_is_mandatory():
    with pytest.raises(SecretConfigurationError, match="AEGIS_PRODUCTION"):
        ProductionSettings.from_env({})


def test_secret_file_inputs_are_materialized_without_environment_mutation(tmp_path):
    env = environment(tmp_path)
    settings = ProductionSettings.from_env(env)
    assert settings.control.db_url.startswith("postgresql://svc_aegis")
    assert settings.redis_url.startswith("redis://default")
    assert "AEGIS_DB_URL" not in env
    assert settings.secret_sources["AEGIS_DB_URL"] == "file"


def test_direct_and_file_secret_is_ambiguous(tmp_path):
    env = environment(tmp_path)
    env["AEGIS_DB_URL"] = "postgresql://other"
    with pytest.raises(SecretConfigurationError, match="only one"):
        ProductionSettings.from_env(env)


def test_complete_single_server_configuration_passes_static_readiness(tmp_path):
    settings = ProductionSettings.from_env(environment(tmp_path))
    assert production_deployment_issues(settings) == []
    require_production_deployment(settings)


def test_every_production_fallback_is_reported(tmp_path):
    env = environment(tmp_path)
    env.pop("AEGIS_REDIS_URL_FILE")
    env.pop("AEGIS_EGRESS_URL")
    env.pop("AEGIS_BROWSER_IMAGE")
    env.pop("AEGIS_SCANNER_LOCK")
    env.pop("AEGIS_OAST_DOMAIN")
    env.pop("AEGIS_LEARN_DB")
    settings = ProductionSettings.from_env(env)
    found = codes(settings)
    assert {"no_redis", "egress_not_enforced", "browser_image_missing",
            "no_scanner_lock", "private_oast_missing", "learning_store_ephemeral"} <= found
    with pytest.raises(ProductionReadinessError):
        require_production_deployment(settings)


def test_mutable_or_unreviewed_releases_are_rejected(tmp_path):
    env = environment(tmp_path)
    lock = tmp_path / "bad-lock.json"
    lock.write_text(json.dumps({"releases": [{
        "name": "scanner", "version": "latest", "sha256": "bad",
        "image": "registry.example/scanner:latest",
        "license_reviewed": False, "output_schema": "aegis.v1",
    }]}), encoding="utf-8")
    env["AEGIS_SCANNER_LOCK"] = str(lock)
    found = codes(ProductionSettings.from_env(env))
    assert {"scanner_digest_invalid", "scanner_image_unpinned", "scanner_license_unreviewed"} <= found


def test_secret_values_in_environment_are_rejected_for_production(tmp_path):
    env = environment(tmp_path)
    path = env.pop("AEGIS_ENCRYPTION_KEY_FILE")
    env["AEGIS_ENCRYPTION_KEY"] = open(path, encoding="utf-8").read()
    assert "secret_not_file" in codes(ProductionSettings.from_env(env))
