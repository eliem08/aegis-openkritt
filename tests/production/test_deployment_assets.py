from pathlib import Path


def text(path):
    return Path(path).read_text(encoding="utf-8")


def test_redis_uses_the_pinned_images_official_privilege_drop():
    entrypoint = text("deploy/redis/secure-entrypoint.sh")
    assert "docker-entrypoint.sh redis-server" in entrypoint
    assert "su-exec" not in entrypoint


def test_postgres_bootstrap_trust_is_removed_before_real_start():
    compose = text("compose.production.yml")
    hardening = text("deploy/postgres/010-harden-hba.sh")
    assert "--auth-local=trust" in compose
    assert "local[[:space:]]+.*[[:space:]]+trust" in hardening
    assert "scram-sha-256" in hardening
    assert "failed to remove PostgreSQL local trust rule" in hardening


def test_postgres_healthcheck_is_authenticated_verify_full_tls():
    compose = text("compose.production.yml")
    assert "PGPASSWORD=$$(cat /run/secrets/postgres_password)" in compose
    assert "sslmode=verify-full" in compose
    assert "pg_isready" not in compose
