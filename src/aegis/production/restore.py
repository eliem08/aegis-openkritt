"""Restore an encrypted backup into an isolated disposable database."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .backup import BackupError, _key, _pg_environment, decrypt_stream

VERIFY_NAME = re.compile(r"^aegis_verify_[a-z0-9_]{1,40}$")


def validate_verification_database(name: str) -> str:
    if not VERIFY_NAME.fullmatch(name):
        raise BackupError("verification database must match aegis_verify_[a-z0-9_]{1,40}")
    return name


def _database_dsn(dsn: str, database: str) -> str:
    parts = urlsplit(dsn)
    return urlunsplit((parts.scheme, parts.netloc, "/" + database, parts.query, ""))


def restore_and_verify(
    dsn: str,
    backup_path: str,
    key_file: str,
    verification_database: str,
    *,
    pg_restore: str = "pg_restore",
) -> dict:
    """Restore, validate core schema, and always drop the disposable database."""
    database = validate_verification_database(verification_database)
    try:
        import psycopg
        from psycopg import sql
    except ImportError as exc:  # pragma: no cover - production dependency
        raise BackupError("restore verification requires psycopg") from exc

    source_dsn = dsn.strip()
    admin_dsn = _database_dsn(source_dsn, "postgres")
    verify_dsn = _database_dsn(source_dsn, database)
    archive = Path(backup_path).resolve()
    temp_name = None
    created = False
    try:
        with tempfile.NamedTemporaryFile(prefix="aegis-restore-", suffix=".dump", delete=False) as temp:
            temp_name = temp.name
            with archive.open("rb") as source:
                decrypt_stream(source, temp, _key(key_file))

        with psycopg.connect(admin_dsn, autocommit=True) as connection:
            with connection.cursor() as cursor:
                cursor.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(database)))
                cursor.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
                created = True

        env, _ = _pg_environment(verify_dsn)
        result = subprocess.run(
            [pg_restore, "--exit-on-error", "--no-owner", "--no-privileges", "--dbname", database, temp_name],
            env=env, capture_output=True, check=False,
        )
        if result.returncode:
            raise BackupError(f"pg_restore failed with exit code {result.returncode}")

        with psycopg.connect(verify_dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM schema_migrations")
                migrations = int(cursor.fetchone()[0])
                cursor.execute(
                    "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'"
                )
                tables = int(cursor.fetchone()[0])
                if migrations <= 0 or tables <= 0:
                    raise BackupError("restored database failed schema integrity checks")
        return {"database": database, "migrations": migrations, "tables": tables, "restored": True}
    finally:
        if temp_name:
            Path(temp_name).unlink(missing_ok=True)
        if created:
            with psycopg.connect(admin_dsn, autocommit=True) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        "WHERE datname=%s AND pid <> pg_backend_pid()",
                        (database,),
                    )
                    cursor.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(database)))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsn-file", required=True)
    parser.add_argument("--key-file", required=True)
    parser.add_argument("--backup", required=True)
    parser.add_argument("--verification-database", required=True)
    parser.add_argument("--report")
    args = parser.parse_args(argv)
    dsn = Path(args.dsn_file).read_text(encoding="utf-8").strip()
    result = restore_and_verify(
        dsn, args.backup, args.key_file, args.verification_database,
    )
    document = json.dumps(result, indent=2) + "\n"
    if args.report:
        Path(args.report).write_text(document, encoding="utf-8")
    else:
        print(document, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
