"""Strict production-deployment validation.

This supplements the generic control-plane checks with infrastructure boundary
checks. It intentionally reports prerequisites rather than inventing pins,
domains, or credentials.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

from aegis.api.prodcheck import Issue, ProductionReadinessError, production_issues
from aegis.oast.service import _is_public
from aegis.supply import UnpinnedImage, verify_image_pin

from .config import ProductionSettings, SECRET_ENV_KEYS


def _scanner_lock_issues(path_text: str | None) -> list[Issue]:
    if not path_text:
        return [Issue("no_scanner_lock", "no scanner release lock is configured")]
    path = Path(path_text)
    if not path.is_file():
        return [Issue("scanner_lock_missing", "scanner release lock file is missing")]
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [Issue("scanner_lock_invalid", "scanner release lock is not valid JSON")]
    releases = document.get("releases") if isinstance(document, dict) else None
    if not isinstance(releases, list) or not releases:
        return [Issue("scanner_lock_empty", "scanner release lock has no releases")]
    issues: list[Issue] = []
    required = {"name", "version", "sha256", "image", "license_reviewed", "output_schema"}
    for index, release in enumerate(releases):
        if not isinstance(release, dict) or not required <= set(release):
            issues.append(Issue("scanner_release_incomplete", f"scanner release {index} is incomplete"))
            continue
        digest = str(release["sha256"])
        if len(digest) != 64 or any(c not in "0123456789abcdefABCDEF" for c in digest):
            issues.append(Issue("scanner_digest_invalid", f"scanner release {index} has an invalid digest"))
        try:
            verify_image_pin(str(release["image"]))
        except UnpinnedImage:
            issues.append(Issue("scanner_image_unpinned", f"scanner release {index} image is mutable"))
        if release["license_reviewed"] is not True:
            issues.append(Issue("scanner_license_unreviewed", f"scanner release {index} lacks license approval"))
    return issues


def production_deployment_issues(settings: ProductionSettings) -> list[Issue]:
    issues = production_issues(
        settings.control,
        dsn=settings.control.db_url,
        oast_domain=settings.oast_domain,
    )
    for secret_name in SECRET_ENV_KEYS:
        if secret_name in {"AEGIS_SIGNING_KEYS", "AEGIS_OPENKRITT_API_KEY"}:
            continue
        if settings.secret_sources.get(secret_name) == "environment":
            issues.append(Issue("secret_not_file", f"{secret_name} must use its _FILE input"))
    if not settings.redis_url:
        issues.append(Issue("no_redis", "no Redis coordination backend is configured"))
    else:
        redis_parts = urlsplit(settings.redis_url)
        if redis_parts.scheme not in {"redis", "rediss"}:
            issues.append(Issue("redis_scheme_invalid", "Redis URL must use redis:// or rediss://"))
        if not redis_parts.password:
            issues.append(Issue("redis_unauthenticated", "Redis URL has no password"))
        if redis_parts.hostname in {None, "localhost", "127.0.0.1", "::1"}:
            issues.append(Issue("redis_dev_host", "Redis host is a local development address"))
    if not settings.egress_enforced or not settings.egress_url:
        issues.append(Issue("egress_not_enforced", "the scoped egress service is not mandatory"))
    if not settings.browser_image:
        issues.append(Issue("browser_image_missing", "no pinned browser image is configured"))
    else:
        try:
            verify_image_pin(settings.browser_image)
        except UnpinnedImage:
            issues.append(Issue("browser_image_unpinned", "browser image is not digest-pinned"))
    issues.extend(_scanner_lock_issues(settings.scanner_lock_path))
    if settings.require_oast:
        if not settings.oast_domain:
            issues.append(Issue("private_oast_missing", "private OAST is required but not configured"))
        elif _is_public(settings.oast_domain):
            issues.append(Issue("public_oast", "a public OAST provider is forbidden"))
    if not settings.control.learn_db_path:
        issues.append(Issue("learning_store_ephemeral", "learning outcomes would use in-memory storage"))
    return issues


def require_production_deployment(settings: ProductionSettings) -> None:
    issues = production_deployment_issues(settings)
    if any(issue.blocking for issue in issues):
        raise ProductionReadinessError(issues)
