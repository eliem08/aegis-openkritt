"""Production-readiness validation (Phase 5; deferred Phase 1 correction).

The dev Docker-Compose defaults — a weak database password, a Compose/localhost
host, an exposed port, no encryption key, single-tenant compatibility — are fine
for local development and unacceptable in production. This module refuses to let a
deployment declare itself production-ready while any of them are present.

``production_issues(config, dsn=...)`` returns a list of :class:`Issue`; a
blocking issue means the deployment must not go live. ``assert_production_ready``
raises with the full list.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

# Credentials and hosts that only ever belong in local development.
DEV_USERNAMES = frozenset({"aegis", "postgres", "root", "admin", "test"})
WEAK_PASSWORDS = frozenset({"aegis", "postgres", "password", "changeme", "admin",
                            "root", "test", "secret", ""})
DEV_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "postgres", "db", "database"})


class ProductionReadinessError(RuntimeError):
    def __init__(self, issues: list[Issue]) -> None:
        self.issues = issues
        blocking = [i for i in issues if i.blocking]
        super().__init__(f"{len(blocking)} blocking production-readiness issue(s): "
                         + "; ".join(i.code for i in blocking))


@dataclass(frozen=True)
class Issue:
    code: str
    message: str
    blocking: bool = True


def production_issues(config, *, dsn: str | None = None, oast_domain: str | None = None) -> list[Issue]:
    issues: list[Issue] = []

    # --- control-plane posture ---
    if not getattr(config, "auth_enabled", True):
        issues.append(Issue("auth_disabled", "authentication is disabled (dev only)"))
    if not getattr(config, "require_signature", True):
        issues.append(Issue("signatures_optional", "authorization signatures are not required"))
    if getattr(config, "is_single_tenant_compat", False):
        issues.append(Issue("single_tenant_compat",
                            "single-tenant compatibility mode has no cross-tenant isolation"))
    if not getattr(config, "encryption_key", None):
        issues.append(Issue("no_encryption_key", "no encryption-at-rest key configured"))
    if not (getattr(config, "signing_keys", None) or getattr(config, "signing_public_keys", None)):
        issues.append(Issue("no_signing_keys", "no authorization signing keys configured"))

    api_keys = getattr(config, "api_keys", {}) or {}
    if not api_keys:
        issues.append(Issue("no_api_keys", "no API keys configured"))
    elif any(not p.tenant_id for p in api_keys.values()):
        issues.append(Issue("untenanted_api_key", "an API key is not bound to a tenant"))

    # --- database: HA + credentials ---
    db_url = dsn or getattr(config, "db_url", None)
    if not db_url:
        if getattr(config, "db_path", None):
            issues.append(Issue("sqlite_not_ha",
                                "SQLite is a supervised single-node option, not production HA"))
        else:
            issues.append(Issue("no_durable_db", "no durable database configured (in-memory)"))
    else:
        issues.extend(_dsn_issues(db_url))

    # --- OAST ---
    if oast_domain is not None:
        from aegis.oast.service import _is_public

        if _is_public(oast_domain):
            issues.append(Issue("public_oast", f"{oast_domain!r} is a public OAST server"))

    return issues


def _dsn_issues(dsn: str) -> list[Issue]:
    issues: list[Issue] = []
    parts = urlsplit(dsn)
    user = (parts.username or "").lower()
    password = parts.password or ""
    host = (parts.hostname or "").lower()
    query = parse_qs(parts.query)
    sslmode = (query.get("sslmode", [""])[0]).lower()

    if password in WEAK_PASSWORDS:
        issues.append(Issue("weak_db_password", "database password is a known dev/default value"))
    if user in DEV_USERNAMES and password in WEAK_PASSWORDS:
        issues.append(Issue("dev_db_credentials", f"dev database credentials ({user}/****)"))
    if host in DEV_HOSTS:
        issues.append(Issue("dev_db_host", f"database host {host!r} is a dev/Compose default"))
    if sslmode not in ("require", "verify-ca", "verify-full"):
        issues.append(Issue("db_connection_unencrypted",
                            "database connection is not TLS-enforced (set sslmode=require or stronger)"))
    return issues


def assert_production_ready(config, *, dsn: str | None = None, oast_domain: str | None = None) -> None:
    issues = production_issues(config, dsn=dsn, oast_domain=oast_domain)
    if any(i.blocking for i in issues):
        raise ProductionReadinessError(issues)
