"""Versioned, checksum-verified schema migrations (Phase 1 correction).

Replaces the create-if-not-exists startup with an ordered migration history. At
startup the runner applies pending *forward* migrations under a database lock and
records each in a ``schema_migrations`` table. It fails closed if:

* an applied migration's checksum no longer matches the code (tampered/edited
  migration), or
* the database contains a migration version the code does not know (the DB was
  migrated by a newer build — a downgrade is refused).

SQLite and Postgres each supply an engine-specific migration list but expose the
same logical schema version and pass the same runner tests.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable


class MigrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str  # engine-specific DDL (may contain multiple statements)

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.sql.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_migrations(
    migrations: list[Migration],
    *,
    execute_script: Callable[[str], object],
    execute: Callable[..., object],
    query: Callable[..., list],
    placeholder: str = "?",
) -> int:
    """Apply pending migrations; return the final schema version.

    ``execute_script(sql)`` applies a migration's (possibly multi-statement) DDL.
    ``execute(sql, params)`` runs a single parametrised statement.
    ``query(sql, params) -> rows`` reads. ``placeholder`` is ``?`` or ``%s``.
    """
    execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations "
        "(version INTEGER PRIMARY KEY, name TEXT, checksum TEXT, applied_at TEXT)"
    )
    rows = query("SELECT version, name, checksum FROM schema_migrations")
    applied = {int(r[0]): (r[1], r[2]) for r in rows}
    known = {m.version: m for m in migrations}

    for version, (_name, checksum) in applied.items():
        if version not in known:
            raise MigrationError(
                f"database has migration {version} unknown to this build; refusing (downgrade)"
            )
        if known[version].checksum != checksum:
            raise MigrationError(
                f"migration {version} checksum mismatch; refusing (schema/migration tampered)"
            )

    for migration in sorted(migrations, key=lambda m: m.version):
        if migration.version in applied:
            continue
        execute_script(migration.sql)
        execute(
            f"INSERT INTO schema_migrations(version, name, checksum, applied_at) "
            f"VALUES ({placeholder},{placeholder},{placeholder},{placeholder})",
            (migration.version, migration.name, migration.checksum, _now_iso()),
        )

    return max(known) if known else 0
