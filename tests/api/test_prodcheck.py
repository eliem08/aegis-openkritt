"""Production-readiness validation (Phase 5; closes the dev-Compose-defaults
correction). The dev Compose configuration must be rejected; a hardened one passes.
"""

from __future__ import annotations

import pytest

from aegis.api import ApiPrincipal, ControlPlaneConfig, Role
from aegis.api.prodcheck import (
    ProductionReadinessError,
    assert_production_ready,
    production_issues,
)

# The values the dev docker-compose ships with.
COMPOSE_DSN = "postgresql://aegis:aegis@postgres:5432/aegis"
HARDENED_DSN = "postgresql://svc_aegis:Q8x!v2n7$kLmP@db.prod.internal:5432/aegis?sslmode=verify-full"


def dev_config():
    # Auth on, but everything else a local-dev default.
    return ControlPlaneConfig(
        api_keys={"k": ApiPrincipal("k", Role.OPERATOR)},   # no tenant -> compat mode
        signing_keys={"kid": "s"}, db_url=COMPOSE_DSN)


def hardened_config():
    return ControlPlaneConfig(
        api_keys={"k": ApiPrincipal("k", Role.OPERATOR, tenant_id="tenant-a")},
        signing_public_keys={"kid": "ab" * 32}, require_signature=True, auth_enabled=True,
        encryption_key="fernet-key", db_url=HARDENED_DSN)


def codes(config, **kw):
    return {i.code for i in production_issues(config, **kw)}


# --- the dev compose config is rejected -------------------------------------

def test_dev_compose_config_is_not_production_ready():
    found = codes(dev_config())
    assert {"weak_db_password", "dev_db_credentials", "dev_db_host",
            "db_connection_unencrypted", "single_tenant_compat", "no_encryption_key"} <= found
    with pytest.raises(ProductionReadinessError):
        assert_production_ready(dev_config())


@pytest.mark.parametrize("dsn,code", [
    ("postgresql://aegis:aegis@db.prod:5432/aegis?sslmode=require", "dev_db_credentials"),
    ("postgresql://svc:strongpass@localhost:5432/aegis?sslmode=require", "dev_db_host"),
    ("postgresql://svc:Str0ng!pw@db.prod:5432/aegis", "db_connection_unencrypted"),
    ("postgresql://svc:password@db.prod:5432/aegis?sslmode=require", "weak_db_password"),
])
def test_specific_database_exposures_are_flagged(dsn, code):
    assert code in codes(hardened_config(), dsn=dsn)


def test_sqlite_is_not_advertised_as_ha():
    cfg = ControlPlaneConfig(
        api_keys={"k": ApiPrincipal("k", Role.OPERATOR, tenant_id="t")},
        signing_public_keys={"kid": "ab" * 32}, encryption_key="key", db_path="/data/aegis.db")
    assert "sqlite_not_ha" in codes(cfg)


def test_auth_and_signature_posture_is_checked():
    cfg = ControlPlaneConfig(
        api_keys={"k": ApiPrincipal("k", Role.OPERATOR, tenant_id="t")},
        auth_enabled=False, require_signature=False, encryption_key="key", db_url=HARDENED_DSN)
    found = codes(cfg)
    assert "auth_disabled" in found and "signatures_optional" in found


def test_public_oast_domain_is_flagged():
    assert "public_oast" in codes(hardened_config(), dsn=HARDENED_DSN, oast_domain="oast.pro")


# --- a hardened config passes ------------------------------------------------

def test_hardened_config_is_production_ready():
    assert production_issues(hardened_config()) == []
    assert_production_ready(hardened_config(), oast_domain="oast.aegis.internal")   # no raise
